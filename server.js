'use strict';
// ClassyPOS server — no dependencies, only Node.js (v18+).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = __dirname;
const PUBLIC_FILES = new Set(['index.html', 'app.js']); // only these files are served
fs.mkdirSync(DIR, { recursive: true });
const F = { db: path.join(DIR, 'db.json'), users: path.join(DIR, 'users.json'), sess: path.join(DIR, 'sessions.json') };

const rd = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return d; } };
const wr = (f, o) => { const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(o)); fs.renameSync(t, f); };

let store = rd(F.db, { version: 0, db: null });
let users = rd(F.users, []);
let sess = rd(F.sess, {});
for (const t of Object.keys(sess)) if (sess[t].exp < Date.now()) delete sess[t];

const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) =>
  ({ salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') });
const check = (pw, u) => {
  const h = crypto.scryptSync(pw, u.salt, 64), b = Buffer.from(u.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(h, b);
};

// First run: create the admin account.
if (!users.length) {
  const email = (process.env.ADMIN_EMAIL || 'admin@classypos.local').toLowerCase();
  let pw = process.env.ADMIN_PASSWORD, generated = false;
  if (!pw) { pw = crypto.randomBytes(9).toString('base64url'); generated = true; }
  users.push({ email, role: 'admin', ...hash(pw) });
  wr(F.users, users);
  console.log('Admin account created: ' + email + (generated ? '  password: ' + pw + '  (change it after login)' : ''));
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.svg': 'image/svg+xml' };
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const body = (req, max = 25e6) => new Promise((ok, no) => {
  let n = 0; const c = [];
  req.on('data', d => { n += d.length; if (n > max) { no({ code: 413 }); req.destroy(); return; } c.push(d); });
  req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c).toString()) : {}); } catch (e) { no({ code: 400 }); } });
  req.on('error', () => no({ code: 400 }));
});
const auth = req => {
  const h = req.headers.authorization || '', t = h.startsWith('Bearer ') ? h.slice(7) : '';
  const s = sess[t];
  if (!s || s.exp < Date.now()) return null;
  const u = users.find(x => x.email === s.email);
  return u ? { u, t } : null;
};
const EMAIL = /^[^\s@'"<>]+@[^\s@'"<>]+\.[^\s@'"<>]+$/;
const fails = {};

http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://x').pathname, m = req.method;

    if (p.startsWith('/api/')) {
      if (p === '/api/login' && m === 'POST') {
        const b = await body(req, 1e4);
        const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
        const f = fails[ip];
        if (f && f.n >= 10 && Date.now() - f.t < 600000) return send(res, 429, { error: 'Too many attempts. Try again in 10 minutes.' });
        const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
        const u = users.find(x => x.email === email);
        const ok = u ? check(pw, u) : (check(pw, { salt: '00', hash: '00'.repeat(64) }), false);
        if (!ok) { fails[ip] = { n: (f && Date.now() - f.t < 600000 ? f.n : 0) + 1, t: Date.now() }; return send(res, 401, { error: 'Wrong email or password' }); }
        delete fails[ip];
        const token = crypto.randomBytes(32).toString('hex');
        sess[token] = { email: u.email, exp: Date.now() + 30 * 864e5 };
        wr(F.sess, sess);
        return send(res, 200, { token, user: { email: u.email, role: u.role } });
      }

      const a = auth(req);
      if (!a) return send(res, 401, { error: 'Login required' });
      const admin = a.u.role === 'admin';

      if (p === '/api/logout' && m === 'POST') { delete sess[a.t]; wr(F.sess, sess); return send(res, 200, { ok: true }); }
      if (p === '/api/version' && m === 'GET') return send(res, 200, { version: store.version });
      if (p === '/api/data' && m === 'GET') return send(res, 200, { version: store.version, db: store.db, user: { email: a.u.email, role: a.u.role } });
      if (p === '/api/data' && m === 'PUT') {
        const b = await body(req);
        if (!b.db || typeof b.db !== 'object') return send(res, 400, { error: 'Bad data' });
        if (b.baseVersion !== store.version) return send(res, 409, { error: 'Data changed on another device', version: store.version });
        store = { version: store.version + 1, db: b.db };
        wr(F.db, store);
        return send(res, 200, { version: store.version });
      }

      if (p === '/api/password' && m === 'POST') {
        const b = await body(req, 1e4), np = String(b.newPassword || '');
        if (!check(String(b.oldPassword || ''), a.u)) return send(res, 400, { error: 'Current password is wrong' });
        if (np.length < 8) return send(res, 400, { error: 'New password must be at least 8 characters' });
        Object.assign(a.u, hash(np));
        wr(F.users, users);
        return send(res, 200, { ok: true });
      }

      if (p === '/api/users') {
        if (!admin) return send(res, 403, { error: 'Admin only' });
        if (m === 'GET') return send(res, 200, users.map(u => ({ email: u.email, role: u.role })));
        if (m === 'POST') {
          const b = await body(req, 1e4), email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
          const role = b.role === 'admin' ? 'admin' : 'staff';
          if (!EMAIL.test(email)) return send(res, 400, { error: 'Invalid email' });
          if (pw.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters' });
          if (users.some(u => u.email === email)) return send(res, 400, { error: 'This email already exists' });
          users.push({ email, role, ...hash(pw) });
          wr(F.users, users);
          return send(res, 200, { ok: true });
        }
      }
      if (p.startsWith('/api/users/') && m === 'DELETE') {
        if (!admin) return send(res, 403, { error: 'Admin only' });
        const email = decodeURIComponent(p.slice(11)).toLowerCase();
        if (email === a.u.email) return send(res, 400, { error: 'You cannot delete yourself' });
        const i = users.findIndex(u => u.email === email);
        if (i < 0) return send(res, 404, { error: 'Not found' });
        users.splice(i, 1);
        for (const t of Object.keys(sess)) if (sess[t].email === email) delete sess[t];
        wr(F.users, users); wr(F.sess, sess);
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'Not found' });
    }

    // Static files
    if (m !== 'GET') return send(res, 405, { error: 'Method not allowed' });
    const rel = p === '/' ? '/index.html' : decodeURIComponent(p);
    const file = path.join(PUB, rel);
    if (!PUBLIC_FILES.has(rel.slice(1)) || !fs.existsSync(file)) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    fs.createReadStream(file).pipe(res);
  } catch (e) {
    if (e && typeof e.code === 'number') return send(res, e.code, { error: e.code === 413 ? 'Too large' : 'Bad request' });
    console.error(e);
    send(res, 500, { error: 'Server error' });
  }
}).listen(PORT, () => console.log('ClassyPOS running on port ' + PORT));
