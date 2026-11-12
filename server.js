const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), multer = require('multer'), path = require('path'), fs = require('fs');
const rateLimit = require('express-rate-limit');

const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(path.join(DIR, 'uploads'), { recursive: true });
const SECRET = process.env.JWT_SECRET || (console.warn('WARNING: set JWT_SECRET env var!'), 'dev-secret-change-me');

const db = new Database(path.join(DIR, 'snapgram.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, bio TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, img TEXT NOT NULL, caption TEXT DEFAULT '', ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS likes(user_id INTEGER, post_id INTEGER, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS saves(user_id INTEGER, post_id INTEGER, PRIMARY KEY(user_id, post_id));
CREATE TABLE IF NOT EXISTS follows(follower INTEGER, following INTEGER, PRIMARY KEY(follower, following));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post_id INTEGER, user_id INTEGER, text TEXT, ts INTEGER);
`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use('/uploads', express.static(path.join(DIR, 'uploads'), { maxAge: '7d' }));
app.get('/', (q, r) => r.sendFile(path.join(__dirname, 'index.html')));

const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' };
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(DIR, 'uploads'),
    filename: (q, f, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 8) + EXT[f.mimetype])
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (q, f, cb) => cb(EXT[f.mimetype] ? null : new Error('Only JPG, PNG, WEBP or GIF images'), !!EXT[f.mimetype])
});

const auth = (req, res, next) => {
  try { req.me = jwt.verify((req.headers.authorization || '').slice(7), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
};
const sign = u => jwt.sign({ id: u.id, username: u.username }, SECRET, { expiresIn: '30d' });
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts, try later' } });

app.post('/api/register', authLimit, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!/^[a-z0-9_.]{3,20}$/.test(username)) return res.status(400).json({ error: 'Username: 3-20 letters, numbers, _ or .' });
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: 'Username already taken' });
  const id = db.prepare('INSERT INTO users(username,pass) VALUES(?,?)').run(username, bcrypt.hashSync(pw, 10)).lastInsertRowid;
  res.json({ token: sign({ id, username }), user: { id, username } });
});

app.post('/api/login', authLimit, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(req.body.username || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass)) return res.status(401).json({ error: 'Wrong username or password' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
});

app.get('/api/me', auth, (req, res) => res.json({ id: req.me.id, username: req.me.username }));

function listPosts(where, params, me) {
  return db.prepare(`SELECT p.id, p.img, p.caption, p.ts, u.username,
    (SELECT COUNT(*) FROM likes WHERE post_id=p.id) likes,
    EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=@me) liked,
    EXISTS(SELECT 1 FROM saves WHERE post_id=p.id AND user_id=@me) saved,
    (SELECT COUNT(*) FROM comments WHERE post_id=p.id) cc
    FROM posts p JOIN users u ON u.id=p.user_id WHERE ${where} ORDER BY p.id DESC LIMIT 60`).all({ me, ...params })
    .map(p => ({ ...p, liked: !!p.liked, saved: !!p.saved }));
}

app.get('/api/posts', auth, (req, res) => {
  const me = req.me.id;
  if (req.query.saved) return res.json(listPosts('p.id IN (SELECT post_id FROM saves WHERE user_id=@me)', {}, me));
  let r = listPosts('(p.user_id=@me OR p.user_id IN (SELECT following FROM follows WHERE follower=@me))', {}, me);
  if (!r.length) r = listPosts('1=1', {}, me); // new users see everyone until they follow people
  res.json(r);
});

app.post('/api/posts', auth, (req, res) => {
  upload.single('image')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Please choose an image' });
    const id = db.prepare('INSERT INTO posts(user_id,img,caption,ts) VALUES(?,?,?,?)')
      .run(req.me.id, req.file.filename, String(req.body.caption || '').slice(0, 500), Date.now()).lastInsertRowid;
    res.json(listPosts('p.id=@id', { id }, req.me.id)[0]);
  });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM posts WHERE id=? AND user_id=?').get(req.params.id, req.me.id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM posts WHERE id=?').run(p.id);
  for (const t of ['likes', 'saves', 'comments']) db.prepare(`DELETE FROM ${t} WHERE post_id=?`).run(p.id);
  fs.unlink(path.join(DIR, 'uploads', p.img), () => {});
  res.json({ ok: true });
});

const toggle = (table, col) => (req, res) => {
  const a = [req.me.id, req.params.id];
  if (!db.prepare('SELECT 1 FROM posts WHERE id=?').get(a[1])) return res.status(404).json({ error: 'Not found' });
  const had = db.prepare(`DELETE FROM ${table} WHERE user_id=? AND post_id=?`).run(...a).changes;
  if (!had) db.prepare(`INSERT INTO ${table}(user_id,post_id) VALUES(?,?)`).run(...a);
  res.json({ [col]: !had, likes: db.prepare('SELECT COUNT(*) c FROM likes WHERE post_id=?').get(a[1]).c });
};
app.post('/api/posts/:id/like', auth, toggle('likes', 'liked'));
app.post('/api/posts/:id/save', auth, toggle('saves', 'saved'));

app.get('/api/posts/:id/comments', auth, (req, res) =>
  res.json(db.prepare('SELECT c.id,c.text,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE post_id=? ORDER BY c.id').all(req.params.id)));

app.post('/api/posts/:id/comments', auth, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 300);
  if (!text) return res.status(400).json({ error: 'Empty comment' });
  const id = db.prepare('INSERT INTO comments(post_id,user_id,text,ts) VALUES(?,?,?,?)').run(req.params.id, req.me.id, text, Date.now()).lastInsertRowid;
  res.json({ id, text, username: req.me.username });
});

app.get('/api/users', auth, (req, res) =>
  res.json(db.prepare("SELECT username,bio FROM users WHERE username LIKE ? LIMIT 20").all('%' + String(req.query.q || '').toLowerCase().replace(/[%_]/g, '') + '%')));

app.get('/api/users/:u', auth, (req, res) => {
  const u = db.prepare('SELECT id,username,bio FROM users WHERE username=?').get(req.params.u);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const c = (q, id) => db.prepare(q).get(id).c;
  res.json({
    username: u.username, bio: u.bio, isMe: u.id === req.me.id,
    followers: c('SELECT COUNT(*) c FROM follows WHERE following=?', u.id),
    following: c('SELECT COUNT(*) c FROM follows WHERE follower=?', u.id),
    isFollowing: !!db.prepare('SELECT 1 FROM follows WHERE follower=? AND following=?').get(req.me.id, u.id),
    posts: listPosts('p.user_id=@uid', { uid: u.id }, req.me.id)
  });
});

app.post('/api/users/:u/follow', auth, (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username=?').get(req.params.u);
  if (!u || u.id === req.me.id) return res.status(400).json({ error: 'Invalid user' });
  const had = db.prepare('DELETE FROM follows WHERE follower=? AND following=?').run(req.me.id, u.id).changes;
  if (!had) db.prepare('INSERT INTO follows VALUES(?,?)').run(req.me.id, u.id);
  res.json({ isFollowing: !had });
});

app.listen(process.env.PORT || 3000, () => console.log('Snapgram running on port ' + (process.env.PORT || 3000)));
