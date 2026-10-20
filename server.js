'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { DatabaseSync } = require('node:sqlite');

const [maj, min] = process.versions.node.split('.').map(Number);
if (maj < 22 || (maj === 22 && min < 13)) {
  console.error('NEX VAULT requires Node.js 22.13+');
  process.exit(1);
}

const CFG = {
  PORT: Number(process.env.PORT ?? 3000),
  DATA_DIR: path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data')),
  BACKUP_DIR: path.resolve(process.env.BACKUP_DIR || path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'backups')),
  PUBLIC_DIR: path.join(__dirname, 'public'),
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123',
  TRUST_PROXY: process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true',
  BANK_WEBHOOK_SECRET: process.env.BANK_WEBHOOK_SECRET || '',
  DELIVERY_MAX_DOWNLOADS: Number(process.env.DELIVERY_MAX_DOWNLOADS || 5),
  DELIVERY_EXPIRES_MIN: Number(process.env.DELIVERY_EXPIRES_MIN || 60),
  SESSION_IDLE_MS: 4 * 3600 * 1000
};
CFG.UPLOAD_DIR = path.join(CFG.DATA_DIR, 'uploads');
CFG.PRIVATE_DIR = path.join(CFG.DATA_DIR, 'private');
CFG.DB_PATH = path.join(CFG.DATA_DIR, 'nexvault.db');

for (const d of [CFG.DATA_DIR, CFG.BACKUP_DIR, CFG.UPLOAD_DIR, CFG.PRIVATE_DIR]) {
  fs.mkdirSync(d, { recursive: true });
}

const ST = {
  INIT: 'Payment initiated',
  PAID: 'Paid (customer confirmed)',
  OK: 'Verified ✔',
  NO: 'Rejected',
  REF: 'Refunded',
  DUP: 'Duplicate UTR ⚠',
  MIS: 'Amount mismatch ⚠'
};
const VALID_STATUSES = new Set(Object.values(ST));

function openDatabaseWithRecovery() {
  const tryOpen = (p) => {
    const d = new DatabaseSync(p);
    const chk = d.prepare('PRAGMA integrity_check').get();
    if (!chk || chk.integrity_check !== 'ok') throw new Error('integrity_check failed');
    d.prepare('SELECT count(*) c FROM sqlite_master').get();
    return d;
  };
  if (fs.existsSync(CFG.DB_PATH)) {
    try {
      return tryOpen(CFG.DB_PATH);
    } catch (_) {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      for (const s of ['', '-wal', '-shm']) {
        if (fs.existsSync(CFG.DB_PATH + s)) {
          try { fs.renameSync(CFG.DB_PATH + s, `${CFG.DB_PATH}.corrupt-${stamp}${s}`); } catch {}
        }
      }
      const backups = fs.existsSync(CFG.BACKUP_DIR)
        ? fs.readdirSync(CFG.BACKUP_DIR).filter(f => f.endsWith('.db')).sort().reverse()
        : [];
      for (const f of backups) {
        const candidate = path.join(CFG.BACKUP_DIR, f);
        try {
          const testDb = tryOpen(candidate);
          testDb.close();
          fs.copyFileSync(candidate, CFG.DB_PATH);
          console.log('database restored from backup:', candidate);
          return tryOpen(CFG.DB_PATH);
        } catch {}
      }
    }
  }
  return new DatabaseSync(CFG.DB_PATH);
}

const db = openDatabaseWithRecovery();
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0, totp_pending TEXT,
    last_totp_step INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, username TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    ip TEXT, ua TEXT, created_at TEXT NOT NULL, last_seen TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS site_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL,
    items_json TEXT NOT NULL, total INTEGER NOT NULL, status TEXT NOT NULL, utr TEXT,
    verify_method TEXT, note TEXT, access_hash TEXT NOT NULL, ip TEXT, ua TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS order_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL,
    type TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS payments (
    utr TEXT PRIMARY KEY, amount INTEGER NOT NULL, source TEXT NOT NULL,
    matched_order_id TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS deliveries (
    product_id TEXT PRIMARY KEY, type TEXT NOT NULL, url TEXT,
    file_path TEXT, filename TEXT, size INTEGER, updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS delivery_tokens (
    token TEXT PRIMARY KEY, order_id TEXT NOT NULL, product_id TEXT NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0, max_downloads INTEGER NOT NULL,
    expires_at TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS media (
    id TEXT PRIMARY KEY, filename TEXT NOT NULL, orig_name TEXT,
    mime TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL,
    ref TEXT, day TEXT NOT NULL, created_at TEXT NOT NULL
  );
`);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `scrypt$${salt}$${crypto.scryptSync(String(password), salt, 64).toString('hex')}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const parts = stored.split('$');
  if (parts.length !== 3) return false;
  const expected = Buffer.from(parts[2], 'hex');
  const actual = crypto.scryptSync(String(password), parts[1], expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
function sha256(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

if (!db.prepare('SELECT username FROM admin_users WHERE username=?').get('admin')) {
  db.prepare('INSERT INTO admin_users (username, pass_hash, updated_at) VALUES (?, ?, ?)').run(
    'admin', hashPassword(CFG.ADMIN_PASSWORD), new Date().toISOString()
  );
}

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0, out = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totpAt(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) { buf[i] = Number(c & 0xffn); c >>= 8n; }
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function makeBackup(kind = 'auto') {
  fs.mkdirSync(CFG.BACKUP_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(CFG.BACKUP_DIR, `nexvault-${kind}-${stamp}-${crypto.randomBytes(2).toString('hex')}.db`);
  db.prepare('VACUUM INTO ?').run(file);
  return file;
}

const rateBuckets = new Map();
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  let b = rateBuckets.get(key);
  if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + windowMs }; rateBuckets.set(key, b); }
  return ++b.count <= limit;
}

function getClientIp(req) {
  if (CFG.TRUST_PROXY && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return req.socket?.remoteAddress || '127.0.0.1';
}

function setSecurityHeaders(res, isApi = true) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (isApi) res.setHeader('Cache-Control', 'no-store');
}

function sendJson(res, status, obj) {
  setSecurityHeaders(res, true);
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length });
  res.end(body);
}

function readBody(req, maxBytes = 100 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0, tooLarge = false;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > maxBytes) tooLarge = true; else chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) return reject(Object.assign(new Error('Payload too large'), { status: 413 }));
      resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

async function readJson(req, maxBytes = 100 * 1024) {
  const buf = await readBody(req, maxBytes);
  if (!buf.length) return {};
  try { return JSON.parse(buf.toString('utf8')); }
  catch { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}

function getAuthSession(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7).trim();
  if (!token) return null;
  const sess = db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(sha256(token));
  if (!sess) return null;
  if (Date.now() - Date.parse(sess.last_seen) > CFG.SESSION_IDLE_MS) {
    db.prepare('DELETE FROM sessions WHERE id=?').run(sess.id);
    return null;
  }
  db.prepare('UPDATE sessions SET last_seen=? WHERE id=?').run(new Date().toISOString(), sess.id);
  return sess;
}

function getLatestCatalogue() {
  const row = db.prepare('SELECT * FROM site_versions ORDER BY id DESC LIMIT 1').get();
  if (!row) return null;
  try { return JSON.parse(row.data_json); } catch { return null; }
}

function calcProductPrice(p) {
  if (p.mrp !== undefined && p.mrp !== null) {
    return Math.floor(Number(p.mrp) * (100 - Number(p.disc || 0)) / 100);
  }
  return Math.floor(Number(p.price || 0));
}

function logOrderEvent(orderId, type, detail = '') {
  db.prepare('INSERT INTO order_events (order_id, type, detail, created_at) VALUES (?, ?, ?, ?)').run(
    orderId, type, detail, new Date().toISOString()
  );
}

function formatOrder(row, includeDeliveries = false) {
  const items = JSON.parse(row.items_json || '[]').map(it => {
    const copy = { id: it.id, name: it.name, price: it.price };
    if (includeDeliveries && row.status === ST.OK) {
      const deliv = db.prepare('SELECT * FROM deliveries WHERE product_id=?').get(it.id);
      if (!deliv) {
        copy.delivery = { type: 'pending' };
      } else if (deliv.type === 'link') {
        copy.delivery = { type: 'link', href: deliv.url };
      } else if (deliv.type === 'file') {
        let tokRow = db.prepare('SELECT * FROM delivery_tokens WHERE order_id=? AND product_id=? ORDER BY created_at DESC LIMIT 1').get(row.id, it.id);
        if (!tokRow) {
          const token = crypto.randomBytes(16).toString('hex');
          const now = new Date();
          const exp = new Date(now.getTime() + CFG.DELIVERY_EXPIRES_MIN * 60000).toISOString();
          db.prepare('INSERT INTO delivery_tokens (token, order_id, product_id, downloads, max_downloads, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?, ?)').run(
            token, row.id, it.id, CFG.DELIVERY_MAX_DOWNLOADS, exp, now.toISOString()
          );
          tokRow = { token };
        }
        copy.delivery = { type: 'file', href: `/api/delivery/${tokRow.token}`, filename: deliv.filename, expires_in_min: CFG.DELIVERY_EXPIRES_MIN };
      }
    }
    return copy;
  });
  return {
    id: row.id, name: row.name, phone: row.phone, email: row.email, items,
    total: row.total, status: row.status, utr: row.utr || '',
    verify_method: row.verify_method || null, note: row.note || '',
    created_at: row.created_at, updated_at: row.updated_at
  };
}

function recordBankPayment(utr, amount, source) {
  const cleanUtr = String(utr || '').trim();
  const numAmount = Number(amount);
  if (!/^\d{12}$/.test(cleanUtr) || !Number.isFinite(numAmount) || numAmount <= 0) {
    return { status: 400, body: { ok: false, error: 'invalid_payment' } };
  }
  if (db.prepare('SELECT utr FROM payments WHERE utr=?').get(cleanUtr)) {
    return { status: 409, body: { ok: false, error: 'duplicate_utr' } };
  }
  const now = new Date().toISOString();
  const order = db.prepare('SELECT * FROM orders WHERE utr=?').get(cleanUtr);
  if (!order) {
    db.prepare('INSERT INTO payments (utr, amount, source, matched_order_id, created_at) VALUES (?, ?, ?, NULL, ?)').run(cleanUtr, numAmount, source, now);
    return { status: 200, body: { ok: true, result: 'stored' } };
  }
  if (order.total === numAmount) {
    db.prepare('UPDATE orders SET status=?, verify_method=?, updated_at=? WHERE id=?').run(ST.OK, 'bank_ledger', now, order.id);
    db.prepare('INSERT INTO payments (utr, amount, source, matched_order_id, created_at) VALUES (?, ?, ?, ?, ?)').run(cleanUtr, numAmount, source, order.id, now);
    logOrderEvent(order.id, 'verified', `Verified via ${source} (${cleanUtr})`);
    return { status: 200, body: { ok: true, result: 'order_verified', order_id: order.id } };
  }
  db.prepare('UPDATE orders SET status=?, updated_at=? WHERE id=?').run(ST.MIS, now, order.id);
  db.prepare('INSERT INTO payments (utr, amount, source, matched_order_id, created_at) VALUES (?, ?, ?, ?, ?)').run(cleanUtr, numAmount, source, order.id, now);
  logOrderEvent(order.id, 'amount_mismatch', `Expected ${order.total}, got ${numAmount}`);
  return { status: 200, body: { ok: true, result: 'amount_mismatch', order_id: order.id } };
}

function escapeLike(str) { return String(str).replace(/[\\%_]/g, '\\$&'); }

function detectImageOrVideoMime(ext, buf) {
  if (!buf || buf.length < 4) return null;
  if (ext === '.png' && buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if ((ext === '.jpg' || ext === '.jpeg') && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (ext === '.gif' && buf.subarray(0, 4).toString('ascii') === 'GIF8') return 'image/gif';
  if (ext === '.webp' && buf.length >= 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
  if ((ext === '.mp4' || ext === '.mov') && buf.length >= 8 && buf.subarray(4, 8).toString('ascii') === 'ftyp') return ext === '.mov' ? 'video/quicktime' : 'video/mp4';
  if (ext === '.webm' && buf.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return 'video/webm';
  return null;
}

const server = http.createServer(async (req, res) => {
  try {
    const ip = getClientIp(req);
    if (!checkRate(`ip:${ip}`, 120, 60000)) {
      return sendJson(res, 429, { ok: false, error: 'rate_limited' });
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const method = req.method.toUpperCase();

    if (pathname === '/api/catalogue' && method === 'GET') {
      const cat = getLatestCatalogue() || { categories: [], products: [], storeName: 'NEX VAULT', currency: '₹' };
      return sendJson(res, 200, { ok: true, catalogue: cat });
    }

    if (pathname === '/api/orders' && method === 'POST') {
      const body = await readJson(req);
      const name = String(body.name || '').trim();
      const phone = String(body.phone || '').trim();
      const email = String(body.email || '').trim();
      const items = Array.isArray(body.items) ? body.items : [];
      const note = String(body.note || '').trim();
      const utr = String(body.utr || '').trim();

      if (!name || !phone || !email || !items.length) {
        return sendJson(res, 400, { ok: false, error: 'missing_fields' });
      }
      if (!/^\d{10}$/.test(phone)) {
        return sendJson(res, 400, { ok: false, error: 'invalid_phone' });
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return sendJson(res, 400, { ok: false, error: 'invalid_email' });
      }

      const cat = getLatestCatalogue();
      if (!cat || !Array.isArray(cat.products)) {
        return sendJson(res, 500, { ok: false, error: 'store_not_configured' });
      }

      const prodMap = new Map(cat.products.map(p => [p.id, p]));
      let calcTotal = 0;
      const verifiedItems = [];
      for (const it of items) {
        const prod = prodMap.get(it.id);
        if (!prod) return sendJson(res, 400, { ok: false, error: `product_not_found:${it.id}` });
        const price = calcProductPrice(prod);
        calcTotal += price;
        verifiedItems.push({ id: prod.id, name: prod.name, price });
      }

      const orderId = 'NV' + crypto.randomBytes(3).toString('hex').toUpperCase();
      const accessHash = crypto.randomBytes(16).toString('hex');
      const now = new Date().toISOString();
      let status = ST.INIT;
      let verifyMethod = null;

      if (utr) {
        if (!/^\d{12}$/.test(utr)) {
          return sendJson(res, 400, { ok: false, error: 'invalid_utr_format' });
        }
        if (db.prepare('SELECT id FROM orders WHERE utr=?').get(utr)) {
          status = ST.DUP;
        } else {
          const pay = db.prepare('SELECT * FROM payments WHERE utr=?').get(utr);
          if (pay) {
            if (pay.amount === calcTotal) {
              status = ST.OK;
              verifyMethod = pay.source;
              db.prepare('UPDATE payments SET matched_order_id=? WHERE utr=?').run(orderId, utr);
            } else {
              status = ST.MIS;
              db.prepare('UPDATE payments SET matched_order_id=? WHERE utr=?').run(orderId, utr);
            }
          } else {
            status = ST.PAID;
            verifyMethod = 'customer_utr';
          }
        }
      }

      db.prepare(`
        INSERT INTO orders (id, name, phone, email, items_json, total, status, utr, verify_method, note, access_hash, ip, ua, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        orderId, name, phone, email, JSON.stringify(verifiedItems), calcTotal, status,
        utr || null, verifyMethod, note, accessHash, ip, req.headers['user-agent'] || '', now, now
      );

      logOrderEvent(orderId, 'created', `Order created with status: ${status}`);

      db.prepare('INSERT INTO analytics_events (type, ref, day, created_at) VALUES (?, ?, ?, ?)').run(
        'order', null, now.slice(0, 10), now
      );

      return sendJson(res, 200, { ok: true, order_id: orderId, total: calcTotal, status });
    }

    const orderTrackMatch = pathname.match(/^\/api\/orders\/([A-Za-z0-9]+)$/);
    if (orderTrackMatch && method === 'GET') {
      const id = orderTrackMatch[1].toUpperCase();
      const row = db.prepare('SELECT * FROM orders WHERE id=?').get(id);
      if (!row) return sendJson(res, 404, { ok: false, error: 'not_found' });
      return sendJson(res, 200, { ok: true, order: formatOrder(row, true) });
    }

    if (pathname === '/api/webhook/bank' && method === 'POST') {
      const sig = req.headers['x-webhook-signature'] || '';
      const rawBody = await readBody(req, 1024 * 1024);
      if (CFG.BANK_WEBHOOK_SECRET) {
        const expectedSig = crypto.createHmac('sha256', CFG.BANK_WEBHOOK_SECRET).update(rawBody).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
          return sendJson(res, 401, { ok: false, error: 'invalid_signature' });
        }
      }
      let payload;
      try { payload = JSON.parse(rawBody.toString('utf8')); } catch { return sendJson(res, 400, { ok: false, error: 'invalid_json' }); }
      const resObj = recordBankPayment(payload.utr, payload.amount, payload.source || 'bank_webhook');
      return sendJson(resObj.status, resObj.body);
    }

    const delivTokenMatch = pathname.match(/^\/api\/delivery\/([a-f0-9]{32})$/);
    if (delivTokenMatch && method === 'GET') {
      const token = delivTokenMatch[1];
      const tokRow = db.prepare('SELECT * FROM delivery_tokens WHERE token=?').get(token);
      if (!tokRow) return sendJson(res, 404, { ok: false, error: 'invalid_token' });
      if (Date.now() > Date.parse(tokRow.expires_at)) return sendJson(res, 410, { ok: false, error: 'token_expired' });
      if (tokRow.downloads >= tokRow.max_downloads) return sendJson(res, 403, { ok: false, error: 'download_limit_reached' });

      const deliv = db.prepare('SELECT * FROM deliveries WHERE product_id=?').get(tokRow.product_id);
      if (!deliv || deliv.type !== 'file') return sendJson(res, 404, { ok: false, error: 'file_not_found' });

      const filePath = path.join(CFG.PRIVATE_DIR, deliv.file_path);
      if (!fs.existsSync(filePath)) return sendJson(res, 404, { ok: false, error: 'file_missing' });

      db.prepare('UPDATE delivery_tokens SET downloads = downloads + 1 WHERE token=?').run(token);
      logOrderEvent(tokRow.order_id, 'download', `Downloaded product ${tokRow.product_id} via token`);

      const fileBuf = fs.readFileSync(filePath);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(deliv.filename)}"`);
      res.setHeader('Content-Length', fileBuf.length);
      res.writeHead(200);
      return res.end(fileBuf);
    }

    if (pathname === '/api/analytics/visit' && method === 'POST') {
      const now = new Date().toISOString();
      db.prepare('INSERT INTO analytics_events (type, ref, day, created_at) VALUES (?, ?, ?, ?)').run(
        'visit', String(req.headers.referer || '').slice(0, 250), now.slice(0, 10), now
      );
      return sendJson(res, 200, { ok: true });
    }

    // Admin Auth Routes
    if (pathname === '/api/admin/login' && method === 'POST') {
      const body = await readJson(req);
      const user = String(body.username || '').trim();
      const pass = String(body.password || '');
      const code = String(body.code || '').trim();

      const admin = db.prepare('SELECT * FROM admin_users WHERE username=?').get(user);
      if (!admin || !verifyPassword(pass, admin.pass_hash)) {
        return sendJson(res, 401, { ok: false, error: 'invalid_credentials' });
      }

      if (admin.totp_enabled) {
        if (!code || code.length !== 6) {
          return sendJson(res, 200, { ok: true, require_totp: true });
        }
        const nowStep = Math.floor(Date.now() / 30000);
        let validTotp = false;
        for (let s = nowStep - 1; s <= nowStep + 1; s++) {
          if (totpAt(admin.totp_secret, s) === code) { validTotp = true; break; }
        }
        if (!validTotp) return sendJson(res, 401, { ok: false, error: 'invalid_totp' });
      }

      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = sha256(token);
      const sessId = crypto.randomUUID();
      const now = new Date().toISOString();

      db.prepare('INSERT INTO sessions (id, username, token_hash, ip, ua, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        sessId, admin.username, tokenHash, ip, req.headers['user-agent'] || '', now, now
      );

      return sendJson(res, 200, { ok: true, token });
    }

    // Protected Admin Routes
    const sess = getAuthSession(req);
    if (pathname.startsWith('/api/admin/')) {
      if (!sess) return sendJson(res, 401, { ok: false, error: 'unauthorized' });

      if (pathname === '/api/admin/logout' && method === 'POST') {
        db.prepare('DELETE FROM sessions WHERE id=?').run(sess.id);
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === '/api/admin/catalogue' && method === 'GET') {
        const cat = getLatestCatalogue();
        return sendJson(res, 200, { ok: true, catalogue: cat });
      }

      if (pathname === '/api/admin/catalogue' && method === 'POST') {
        const body = await readJson(req);
        if (!body.catalogue || typeof body.catalogue !== 'object') {
          return sendJson(res, 400, { ok: false, error: 'invalid_catalogue' });
        }
        const jsonStr = JSON.stringify(body.catalogue);
        db.prepare('INSERT INTO site_versions (data_json, created_at) VALUES (?, ?)').run(jsonStr, new Date().toISOString());
        return sendJson(res, 200, { ok: true });
      }

      const delivFileMatch = pathname.match(/^\/api\/admin\/deliveries\/([A-Za-z0-9_\-]+)$/);
      if (delivFileMatch && method === 'POST') {
        const origName = path.basename(parsedUrl.searchParams.get('filename') || 'file.zip');
        const ext = path.extname(origName).toLowerCase();
        const buf = await readBody(req, 50 * 1024 * 1024);
        const storedName = `${crypto.randomBytes(12).toString('hex')}${ext}`;
        fs.writeFileSync(path.join(CFG.PRIVATE_DIR, storedName), buf);
        db.prepare(`INSERT INTO deliveries (product_id, type, url, file_path, filename, size, updated_at) VALUES (?, 'file', NULL, ?, ?, ?, ?) ON CONFLICT(product_id) DO UPDATE SET type='file', url=NULL, file_path=excluded.file_path, filename=excluded.filename, size=excluded.size, updated_at=excluded.updated_at`).run(delivFileMatch[1], storedName, origName, buf.length, new Date().toISOString());
        return sendJson(res, 200, { ok: true, filename: origName, size: buf.length });
      }

      if (pathname === '/api/admin/orders' && method === 'GET') {
        const q = parsedUrl.searchParams.get('q') || '', status = parsedUrl.searchParams.get('status') || '';
        let sql = 'SELECT * FROM orders WHERE 1=1';
        const params = [];
        if (q) {
          const pat = `%${escapeLike(q)}%`;
          sql += " AND (id LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR COALESCE(utr,'') LIKE ? ESCAPE '\\')";
          params.push(pat, pat, pat, pat, pat);
        }
        if (status) { sql += ' AND status = ?'; params.push(status); }
        sql += ' ORDER BY created_at DESC';
        const rows = db.prepare(sql).all(...params).map(r => formatOrder(r, false));
        return sendJson(res, 200, { ok: true, total: rows.length, rows });
      }

      const ordAdminMatch = pathname.match(/^\/api\/admin\/orders\/([A-Za-z0-9]+)$/);
      if (ordAdminMatch && method === 'GET') {
        const id = ordAdminMatch[1].toUpperCase();
        const row = db.prepare('SELECT * FROM orders WHERE id=?').get(id);
        if (!row) return sendJson(res, 404, { ok: false, error: 'not_found' });
        const events = db.prepare('SELECT * FROM order_events WHERE order_id=? ORDER BY id ASC').all(id);
        return sendJson(res, 200, { ok: true, order: { ...formatOrder(row, false), events } });
      }

      if (ordAdminMatch && method === 'PATCH') {
        const id = ordAdminMatch[1].toUpperCase();
        const body = await readJson(req);
        if (!VALID_STATUSES.has(body.status)) return sendJson(res, 400, { ok: false, error: 'invalid_status' });
        if (!db.prepare('SELECT id FROM orders WHERE id=?').get(id)) return sendJson(res, 404, { ok: false, error: 'not_found' });
        db.prepare('UPDATE orders SET status=?, note=?, updated_at=? WHERE id=?').run(body.status, String(body.note || ''), new Date().toISOString(), id);
        logOrderEvent(id, 'status_changed', `Status set to ${body.status}`);
        return sendJson(res, 200, { ok: true, order: formatOrder(db.prepare('SELECT * FROM orders WHERE id=?').get(id), false) });
      }

      if (pathname === '/api/admin/customers' && method === 'GET') {
        const q = parsedUrl.searchParams.get('q') || '';
        let sql = 'SELECT name, phone, email, COUNT(*) orders, SUM(total) spent, MAX(created_at) last_order FROM orders';
        const params = [];
        if (q) {
          const pat = `%${escapeLike(q)}%`;
          sql += " WHERE (name LIKE ? ESCAPE '\\' OR phone LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')";
          params.push(pat, pat, pat);
        }
        sql += ' GROUP BY phone, email ORDER BY last_order DESC';
        return sendJson(res, 200, { ok: true, rows: db.prepare(sql).all(...params) });
      }

      if (pathname === '/api/admin/stats' && method === 'GET') {
        const visitsTotal = db.prepare("SELECT COUNT(*) c FROM analytics_events WHERE type='visit'").get().c;
        const allOrders = db.prepare('SELECT status, total FROM orders').all();
        let verified = 0, flagged = 0, pending = 0, rejected = 0, revenue = 0;
        for (const o of allOrders) {
          if (o.status === ST.OK) { verified++; revenue += o.total; }
          else if (o.status === ST.DUP || o.status === ST.MIS) flagged++;
          else if (o.status === ST.NO || o.status === ST.REF) rejected++;
          else pending++;
        }
        return sendJson(res, 200, { ok: true, visits: { total: visitsTotal }, orders: { total: allOrders.length, verified, flagged, pending, rejected, revenue } });
      }

      if (pathname === '/api/admin/export/orders.csv' && method === 'GET') {
        const rows = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all();
        const csvCell = v => {
          let s = String(v == null ? '' : v);
          if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
          return '"' + s.replace(/"/g, '""') + '"';
        };
        const header = ['Order ID', 'Date', 'Name', 'Phone', 'Email', 'Total', 'Status', 'UTR'].map(csvCell).join(',');
        const lines = rows.map(r => [r.id, r.created_at, r.name, r.phone, r.email, r.total, r.status, r.utr || ''].map(csvCell).join(','));
        setSecurityHeaders(res, true);
        res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="orders.csv"' });
        return res.end([header, ...lines].join('\n'));
      }

      if (pathname === '/api/admin/upload' && method === 'POST') {
        const origName = path.basename(parsedUrl.searchParams.get('filename') || 'image.png');
        const ext = path.extname(origName).toLowerCase();
        if (!new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif', '.mp4', '.webm', '.mov']).has(ext)) {
          return sendJson(res, 415, { ok: false, error: 'unsupported_media_type' });
        }
        const buf = await readBody(req, 20 * 1024 * 1024);
        const mime = detectImageOrVideoMime(ext, buf);
        if (!mime) return sendJson(res, 400, { ok: false, error: 'invalid_file_content' });
        const id = crypto.randomBytes(12).toString('hex'), filename = `${id}${ext}`;
        fs.writeFileSync(path.join(CFG.UPLOAD_DIR, filename), buf);
        db.prepare('INSERT INTO media (id, filename, orig_name, mime, size, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, filename, origName, mime, buf.length, new Date().toISOString());
        return sendJson(res, 200, { ok: true, id, url: `/uploads/${filename}`, mime, size: buf.length });
      }

      if (pathname === '/api/admin/media' && method === 'GET') {
        const rows = db.prepare('SELECT * FROM media ORDER BY created_at DESC').all().map(m => ({ ...m, url: `/uploads/${m.filename}` }));
        return sendJson(res, 200, { ok: true, rows });
      }

      const mediaDel = pathname.match(/^\/api\/admin\/media\/([a-f0-9]{24})$/);
      if (mediaDel && method === 'DELETE') {
        const row = db.prepare('SELECT * FROM media WHERE id=?').get(mediaDel[1]);
        if (row) {
          const p = path.join(CFG.UPLOAD_DIR, row.filename);
          if (fs.existsSync(p)) fs.unlinkSync(p);
          db.prepare('DELETE FROM media WHERE id=?').run(row.id);
        }
        return sendJson(res, 200, { ok: true });
      }

      if (pathname === '/api/admin/backup' && method === 'GET') {
        const file = makeBackup('manual'), buf = fs.readFileSync(file);
        setSecurityHeaders(res, true);
        res.writeHead(200, { 'Content-Type': 'application/x-sqlite3', 'Content-Disposition': `attachment; filename="${path.basename(file)}"`, 'Content-Length': buf.length });
        return res.end(buf);
      }

      if (pathname === '/api/admin/backups' && method === 'GET') {
        const rows = fs.existsSync(CFG.BACKUP_DIR)
          ? fs.readdirSync(CFG.BACKUP_DIR).filter(f => f.endsWith('.db')).map(f => {
              const st = fs.statSync(path.join(CFG.BACKUP_DIR, f));
              return { name: f, size: st.size, created_at: st.mtime.toISOString() };
            })
          : [];
        return sendJson(res, 200, { ok: true, rows });
      }
    }

    if (pathname.startsWith('/api/')) return sendJson(res, 404, { ok: false, error: 'not_found' });

    const uploadMatch = pathname.match(/^\/uploads\/([a-f0-9]{24}\.(?:png|jpe?g|webp|gif|mp4|webm|mov))$/);
    if (uploadMatch && method === 'GET') {
      const file = path.join(CFG.UPLOAD_DIR, uploadMatch[1]);
      if (!fs.existsSync(file)) { res.writeHead(404); return res.end(); }
      const stat = fs.statSync(file), ext = path.extname(file).toLowerCase();
      const mimes = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime' };
      setSecurityHeaders(res, false);
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Content-Type', mimes[ext] || 'application/octet-stream');
      if (req.headers.range) {
        const m = req.headers.range.match(/bytes=(\d+)-(\d*)/);
        if (m) {
          const start = Number(m[1]), end = m[2] ? Math.min(stat.size - 1, Number(m[2])) : stat.size - 1;
          if (start <= end && start < stat.size) {
            const chunk = fs.readFileSync(file).subarray(start, end + 1);
            res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${stat.size}`, 'Content-Length': chunk.length });
            return res.end(chunk);
          }
        }
      }
      const buf = fs.readFileSync(file);
      res.writeHead(200, { 'Content-Length': buf.length });
      return res.end(buf);
    }

    const pageMap = { '/': 'index.html', '/index.html': 'index.html', '/admin': 'admin.html', '/admin.html': 'admin.html', '/order': 'order.html', '/order.html': 'order.html' };
    if (method === 'GET' && pageMap[pathname]) {
      const filePath = path.join(CFG.PUBLIC_DIR, pageMap[pathname]);
      if (!fs.existsSync(filePath)) { res.writeHead(404); return res.end('Not found'); }
      const rawHtml = fs.readFileSync(filePath);
      setSecurityHeaders(res, false);
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: blob: https: http:; media-src 'self' data: blob: https: http:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; connect-src 'self' https: http:; frame-src https://www.youtube.com https://drive.google.com;");
      if (String(req.headers['accept-encoding'] || '').includes('gzip')) {
        const gz = zlib.gzipSync(rawHtml);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'gzip', 'Content-Length': gz.length });
        return res.end(gz);
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': rawHtml.length });
      return res.end(rawHtml);
    }

    setSecurityHeaders(res, true);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  } catch (err) {
    if (err && (err.status === 400 || err.status === 413)) return sendJson(res, err.status, { ok: false, error: err.message });
    return sendJson(res, 500, { ok: false, error: 'internal_error' });
  }
});

if (require.main === module && !process.env.__NV_SCRIPT) {
  server.listen(CFG.PORT, () => console.log(`NEX VAULT server v2 listening on http://127.0.0.1:${CFG.PORT}`));
}

module.exports = { server, db, ST, totpAt, makeBackup, CFG };
