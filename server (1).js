const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), multer = require('multer'), path = require('path');
const rateLimit = require('express-rate-limit');

const { DATABASE_URL, SUPABASE_URL, SUPABASE_KEY } = process.env;
if (!DATABASE_URL || !SUPABASE_URL || !SUPABASE_KEY) { console.error('Missing env vars: DATABASE_URL, SUPABASE_URL, SUPABASE_KEY'); process.exit(1); }
const SECRET = process.env.JWT_SECRET || (console.warn('WARNING: set JWT_SECRET env var!'), 'dev-secret-change-me');
const SB = SUPABASE_URL.replace(/\/+$/, '');
const sbHeaders = extra => ({ apikey: SUPABASE_KEY, Authorization: 'Bearer ' + SUPABASE_KEY, ...extra });

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const q = (sql, p = []) => pool.query(sql, p);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' };
const upload = multer({
  storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(EXT[f.mimetype] ? null : new Error('Only JPG, PNG, WEBP or GIF images'), !!EXT[f.mimetype])
});
async function putImage(f) {
  const name = Date.now() + '-' + Math.random().toString(36).slice(2, 8) + EXT[f.mimetype];
  const r = await fetch(`${SB}/storage/v1/object/uploads/${name}`, { method: 'POST', headers: sbHeaders({ 'Content-Type': f.mimetype }), body: f.buffer });
  if (!r.ok) throw new Error('Image upload failed');
  return `${SB}/storage/v1/object/public/uploads/${name}`;
}
const delImage = url => fetch(`${SB}/storage/v1/object/uploads/${url.split('/').pop()}`, { method: 'DELETE', headers: sbHeaders() }).catch(() => {});

const w = f => (req, res, next) => f(req, res, next).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const auth = (req, res, next) => {
  try { req.me = jwt.verify((req.headers.authorization || '').slice(7), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
};
const sign = u => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '30d' });
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts, try later' } });

app.post('/api/register', authLimit, w(async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^[a-z0-9_.]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 letters, numbers, _ or .' });
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if ((await q('SELECT 1 FROM users WHERE username=$1', [username])).rowCount) return res.status(409).json({ error: 'Username already taken' });
  const id = (await q('INSERT INTO users(username,pass) VALUES($1,$2) RETURNING id', [username, bcrypt.hashSync(pw, 10)])).rows[0].id;
  res.json({ token: sign({ id, username }), user: { id, username } });
}));

app.post('/api/login', authLimit, w(async (req, res) => {
  const u = (await q('SELECT * FROM users WHERE username=$1', [String(req.body.username || '').trim().toLowerCase()])).rows[0];
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass)) return res.status(401).json({ error: 'Wrong username or password' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
}));

app.get('/api/me', auth, (req, res) => res.json({ id: req.me.id, username: req.me.username }));

// $1 is always the logged-in user's id; extra params start at $2
const listPosts = async (where, params, me) => (await q(`SELECT p.id, p.img, p.caption, p.ts, u.username,
  (SELECT COUNT(*)::int FROM likes WHERE post_id=p.id) likes,
  EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=$1) liked,
  EXISTS(SELECT 1 FROM saves WHERE post_id=p.id AND user_id=$1) saved,
  (SELECT COUNT(*)::int FROM comments WHERE post_id=p.id) cc
  FROM posts p JOIN users u ON u.id=p.user_id WHERE ${where} ORDER BY p.id DESC LIMIT 60`, [me, ...params])).rows;

app.get('/api/posts', auth, w(async (req, res) => {
  const me = req.me.id;
  if (req.query.saved) return res.json(await listPosts('p.id IN (SELECT post_id FROM saves WHERE user_id=$1)', [], me));
  let r = await listPosts('(p.user_id=$1 OR p.user_id IN (SELECT following FROM follows WHERE follower=$1))', [], me);
  if (!r.length) r = await listPosts('TRUE', [], me); // new users see everyone until they follow people
  res.json(r);
}));

app.post('/api/posts', auth, (req, res) => {
  upload.single('image')(req, res, async err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Please choose an image' });
    try {
      const url = await putImage(req.file);
      const id = (await q('INSERT INTO posts(user_id,img,caption,ts) VALUES($1,$2,$3,$4) RETURNING id',
        [req.me.id, url, String(req.body.caption || '').slice(0, 500), Date.now()])).rows[0].id;
      res.json((await listPosts('p.id=$2', [id], req.me.id))[0]);
    } catch (e) { console.error(e); res.status(500).json({ error: e.message || 'Server error' }); }
  });
});

app.delete('/api/posts/:id', auth, w(async (req, res) => {
  const p = (await q('SELECT * FROM posts WHERE id=$1 AND user_id=$2', [req.params.id, req.me.id])).rows[0];
  if (!p) return res.status(404).json({ error: 'Not found' });
  for (const t of ['likes', 'saves', 'comments', 'posts']) await q(`DELETE FROM ${t} WHERE ${t === 'posts' ? 'id' : 'post_id'}=$1`, [p.id]);
  delImage(p.img);
  res.json({ ok: true });
}));

const toggle = (table, col) => w(async (req, res) => {
  const a = [req.me.id, req.params.id];
  if (!(await q('SELECT 1 FROM posts WHERE id=$1', [a[1]])).rowCount) return res.status(404).json({ error: 'Not found' });
  const had = (await q(`DELETE FROM ${table} WHERE user_id=$1 AND post_id=$2`, a)).rowCount;
  if (!had) await q(`INSERT INTO ${table}(user_id,post_id) VALUES($1,$2)`, a);
  res.json({ [col]: !had, likes: (await q('SELECT COUNT(*)::int c FROM likes WHERE post_id=$1', [a[1]])).rows[0].c });
});
app.post('/api/posts/:id/like', auth, toggle('likes', 'liked'));
app.post('/api/posts/:id/save', auth, toggle('saves', 'saved'));

app.get('/api/posts/:id/comments', auth, w(async (req, res) =>
  res.json((await q('SELECT c.id,c.text,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE post_id=$1 ORDER BY c.id', [req.params.id])).rows)));

app.post('/api/posts/:id/comments', auth, w(async (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 300);
  if (!text) return res.status(400).json({ error: 'Empty comment' });
  const id = (await q('INSERT INTO comments(post_id,user_id,text,ts) VALUES($1,$2,$3,$4) RETURNING id', [req.params.id, req.me.id, text, Date.now()])).rows[0].id;
  res.json({ id, text, username: req.me.username });
}));

app.get('/api/users', auth, w(async (req, res) =>
  res.json((await q('SELECT username,bio FROM users WHERE username LIKE $1 LIMIT 20', ['%' + String(req.query.q || '').toLowerCase().replace(/[%_]/g, '') + '%'])).rows)));

app.get('/api/users/:u', auth, w(async (req, res) => {
  const u = (await q('SELECT id,username,bio FROM users WHERE username=$1', [req.params.u])).rows[0];
  if (!u) return res.status(404).json({ error: 'User not found' });
  const c = async (sql, id) => (await q(sql, [id])).rows[0].c;
  res.json({
    username: u.username, bio: u.bio, isMe: u.id === req.me.id,
    followers: await c('SELECT COUNT(*)::int c FROM follows WHERE following=$1', u.id),
    following: await c('SELECT COUNT(*)::int c FROM follows WHERE follower=$1', u.id),
    isFollowing: !!(await q('SELECT 1 FROM follows WHERE follower=$1 AND following=$2', [req.me.id, u.id])).rowCount,
    posts: await listPosts('p.user_id=$2', [u.id], req.me.id)
  });
}));

app.post('/api/users/:u/follow', auth, w(async (req, res) => {
  const u = (await q('SELECT id FROM users WHERE username=$1', [req.params.u])).rows[0];
  if (!u || u.id === req.me.id) return res.status(400).json({ error: 'Invalid user' });
  const had = (await q('DELETE FROM follows WHERE follower=$1 AND following=$2', [req.me.id, u.id])).rowCount;
  if (!had) await q('INSERT INTO follows VALUES($1,$2)', [req.me.id, u.id]);
  res.json({ isFollowing: !had });
}));

(async () => {
  await q(`
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, bio TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS posts(id SERIAL PRIMARY KEY, user_id INT NOT NULL, img TEXT NOT NULL, caption TEXT DEFAULT '', ts BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS likes(user_id INT, post_id INT, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS saves(user_id INT, post_id INT, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS follows(follower INT, following INT, PRIMARY KEY(follower, following));
CREATE TABLE IF NOT EXISTS comments(id SERIAL PRIMARY KEY, post_id INT, user_id INT, text TEXT, ts BIGINT);`);
  // public bucket for photos (harmless error if it already exists)
  await fetch(`${SB}/storage/v1/bucket`, { method: 'POST', headers: sbHeaders({ 'Content-Type': 'application/json' }), body: JSON.stringify({ id: 'uploads', name: 'uploads', public: true }) }).catch(() => {});
  app.listen(process.env.PORT || 3000, () => console.log('Snapgram running'));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
