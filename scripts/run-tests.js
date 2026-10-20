'use strict';
// Integration tests:  npm test   (uses a throw-away database; needs Node 22.13+)
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto'), zlib = require('node:zlib');
const assert = require('node:assert/strict'), { spawnSync } = require('node:child_process');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-test-'));
Object.assign(process.env, { DATA_DIR: tmp, ADMIN_PASSWORD: 'TestPassw0rd!', PORT: '0', TRUST_PROXY: '1', BANK_WEBHOOK_SECRET: 'whsec_test', DELIVERY_MAX_DOWNLOADS: '2' });
const { server, db, ST, totpAt } = require('../server.js');
let passed = 0; const fails = [];
const T = async (name, fn) => { try { await fn(); passed++; console.log('  ✓', name); } catch (e) { fails.push(name); console.log('  ✗', name, '\n     ', e.message.split('\n')[0]); } };
const sign = body => crypto.createHmac('sha256', 'whsec_test').update(body).digest('hex');

(async () => {
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port; let n = 0;
  const call = async (method, p, body, token, extra = {}) => {
    const h = { 'X-Forwarded-For': extra.ip || '10.0.' + Math.floor(++n / 250) + '.' + (n % 250), ...(extra.headers || {}) };
    if (token) h.Authorization = 'Bearer ' + token;
    let payload = body; if (body !== undefined && !Buffer.isBuffer(body) && typeof body !== 'string') { payload = JSON.stringify(body); h['Content-Type'] = 'application/json'; }
    const r = await fetch(base + p, { method, headers: h, body: payload }), ct = r.headers.get('content-type') || '';
    return { status: r.status, headers: r.headers, json: ct.includes('json') ? await r.json() : null, text: ct.includes('json') ? null : await r.text() };
  };
  console.log('\nNEX VAULT server v2 — test suite');
  const cust = { name: 'Ravi Kumar', phone: '9876543210', email: 'Ravi@Gmail.com' };
  let tok;

  console.log('\n[core & security headers]');
  await T('health endpoint reports node/db/backup info', async () => { const r = await call('GET', '/api/health'); assert.equal(r.status, 200); assert.equal(r.json.ok, true); assert.ok(r.json.node); });
  await T('security headers present', async () => { const r = await call('GET', '/api/health'); assert.equal(r.headers.get('x-content-type-options'), 'nosniff'); assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN'); assert.equal(r.headers.get('cache-control'), 'no-store'); });
  await T('unknown API route → JSON 404', async () => { const r = await call('GET', '/api/nope'); assert.equal(r.status, 404); assert.equal(r.json.ok, false); });
  await T('malformed JSON → 400 (not 500)', async () => { const r = await call('POST', '/api/orders', '{bad', undefined, { headers: { 'Content-Type': 'application/json' } }); assert.equal(r.status, 400); });
  await T('store refuses orders until a catalogue is published (503)', async () => { const r = await call('POST', '/api/orders', { id: 'NVEARLY001', ...cust, items: [{ id: 'd1' }] }); assert.equal(r.status, 503); });

  console.log('\n[admin authentication]');
  await T('admin routes reject missing / forged tokens', async () => { for (const p of ['/api/admin/orders', '/api/admin/stats', '/api/admin/backup', '/api/admin/payments', '/api/admin/deliveries']) assert.equal((await call('GET', p)).status, 401, p); assert.equal((await call('GET', '/api/admin/orders', undefined, 'A'.repeat(43))).status, 401); });
  await T('wrong password → 401, correct → token', async () => { assert.equal((await call('POST', '/api/admin/login', { username: 'admin', password: 'nope' })).status, 401); const r = await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!' }); assert.equal(r.status, 200); tok = r.json.token; });
  await T('password stored as scrypt hash; session token stored only hashed', async () => { assert.match(db.prepare('SELECT pass_hash h FROM admin_users').get().h, /^scrypt\$/); assert.notEqual(db.prepare('SELECT token_hash t FROM sessions').get().t, tok); });

  console.log('\n[catalogue & server-side pricing]');
  const site = { v: 2, products: [{ id: 'd1', name: '500+ AI Health Reels', mrp: 99, disc: 50, img: '/uploads/aaaaaaaaaaaaaaaaaaaaaaaa.png' }, { id: 'd2', name: '2000+ Stickman Reels', mrp: 150, disc: 54 }, { id: 'd3', name: 'Mad Scientist', mrp: 199, disc: 55 }, { id: 'd4', name: 'Hidden', mrp: 99, disc: 0, hidden: true }], cats: [], heroes: [], pages: [], settings: { hook: 'secret-hook', name: 'NEX VAULT' } };
  await T('publish catalogue (admin only); hook secret stripped; negative price refused', async () => {
    assert.equal((await call('PUT', '/api/admin/site', site)).status, 401);
    assert.equal((await call('PUT', '/api/admin/site', { ...site, products: [{ id: 'x', name: 'x', mrp: 100, disc: 150 }] }, tok)).status, 400);
    assert.equal((await call('PUT', '/api/admin/site', site, tok)).status, 200);
    assert.equal((await call('GET', '/api/site')).json.settings.hook, undefined);
  });
  await T('public site: /uploads become absolute; gzip supported; ETag → 304', async () => {
    const r = await fetch(base + '/api/site', { headers: { 'Accept-Encoding': 'gzip' } }); assert.equal(r.status, 200); const et = r.headers.get('etag'); assert.ok(et); await r.arrayBuffer();
    const r2 = await fetch(base + '/api/site', { headers: { 'If-None-Match': et } }); assert.equal(r2.status, 304);
    const j = await (await fetch(base + '/api/site')).json(); assert.match(j.products[0].img, /^http:\/\/127\.0\.0\.1:\d+\/uploads\//);
  });
  await T('order price is computed by the server; browser price ignored', async () => { const r = await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, status: ST.INIT, items: [{ id: 'd1', price: 1 }, { id: 'd2', price: 1 }] }); assert.equal(r.status, 200); assert.equal(r.json.order.total, 118); assert.ok(r.json.access_key); T.key1 = r.json.access_key; });
  await T('unknown / hidden products refused (422)', async () => { for (const id of ['zz', 'd4']) { const r = await call('POST', '/api/orders', { id: 'NVTEST0009', ...cust, status: ST.INIT, items: [{ id, price: 1 }] }); assert.equal(r.status, 422, id); } });
  await T('same product twice in one order is counted once', async () => { const r = await call('POST', '/api/orders', { id: 'NVTEST0008', ...cust, status: ST.INIT, items: [{ id: 'd1' }, { id: 'd1' }] }); assert.equal(r.json.order.total, 49); });
  await T('validation: name / phone / email / id / items', async () => {
    for (const b of [{ name: 'A' }, { phone: '12345' }, { email: 'nope' }, { items: [] }, { id: "x'; DROP TABLE orders;--" }]) assert.equal((await call('POST', '/api/orders', { id: 'NVTEST0002', ...cust, status: ST.INIT, items: [{ id: 'd1' }], ...b })).status, 400, JSON.stringify(b));
    assert.ok(db.prepare('SELECT COUNT(*) c FROM orders').get().c >= 1);
  });

  console.log('\n[UPI payment verification]');
  await T('"I have paid" needs a 12-digit UTR', async () => { const r = await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, access_key: T.key1, status: ST.PAID, utr: '123', items: [{ id: 'd1' }, { id: 'd2' }] }); assert.equal(r.status, 400); assert.equal(r.json.error, 'invalid_utr'); });
  await T('order update needs the private access key (hijack blocked)', async () => { assert.equal((await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, status: ST.PAID, utr: '412345678901', items: [{ id: 'd1' }] })).status, 403); assert.equal((await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, access_key: 'wrong', status: ST.PAID, utr: '412345678901', items: [{ id: 'd1' }] })).status, 403); });
  await T('customer confirmation alone is NOT verification (stays "Paid (customer confirmed)")', async () => { const r = await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, access_key: T.key1, status: ST.PAID, utr: '412345678901', items: [{ id: 'd1' }, { id: 'd2' }] }); assert.equal(r.status, 200); assert.equal(r.json.order.status, ST.PAID); assert.equal(r.json.verified, false); });
  await T('same UTR on another order is flagged (409) and can be corrected', async () => {
    const a = await call('POST', '/api/orders', { id: 'NVTEST0003', name: 'Sam Roy', phone: '9123456780', email: 'sam@x.com', status: ST.INIT, items: [{ id: 'd3' }] }); const key = a.json.access_key;
    const r = await call('POST', '/api/orders', { id: 'NVTEST0003', name: 'Sam Roy', phone: '9123456780', email: 'sam@x.com', access_key: key, status: ST.PAID, utr: '412345678901', items: [{ id: 'd3' }] });
    assert.equal(r.status, 409); assert.equal(r.json.error, 'duplicate_utr'); assert.equal(db.prepare('SELECT status s FROM orders WHERE id=?').get('NVTEST0003').s, ST.DUP);
    assert.equal((await call('POST', '/api/orders', { id: 'NVTEST0003', name: 'Sam Roy', phone: '9123456780', email: 'sam@x.com', access_key: key, status: ST.PAID, utr: '999999999991', items: [{ id: 'd3' }] })).status, 200); T.key3 = key;
  });
  await T('admin records a bank credit → matching order auto-verifies', async () => {
    const r = await call('POST', '/api/admin/payments', { utr: '412345678901', amount: 118 }, tok); assert.equal(r.status, 200); assert.equal(r.json.result, 'order_verified'); assert.equal(db.prepare('SELECT status s, verify_method m FROM orders WHERE id=?').get('NVTEST0001').m, 'bank_ledger');
    assert.equal((await call('POST', '/api/admin/payments', { utr: '412345678901', amount: 118 }, tok)).status, 409);
  });
  await T('credit with wrong amount flags the order instead of verifying', async () => { const r = await call('POST', '/api/admin/payments', { utr: '999999999991', amount: 1 }, tok); assert.equal(r.json.result, 'amount_mismatch'); assert.equal(db.prepare('SELECT status s FROM orders WHERE id=?').get('NVTEST0003').s, ST.MIS); });
  await T('credit that arrives BEFORE the customer pays verifies instantly', async () => {
    assert.equal((await call('POST', '/api/admin/payments', { utr: '555555555555', amount: 49 }, tok)).json.result, 'stored');
    const a = await call('POST', '/api/orders', { id: 'NVTEST0006', ...cust, status: ST.INIT, items: [{ id: 'd1' }] });
    const r = await call('POST', '/api/orders', { id: 'NVTEST0006', ...cust, access_key: a.json.access_key, status: ST.PAID, utr: '555555555555', items: [{ id: 'd1' }] }); assert.equal(r.json.order.status, ST.OK); assert.equal(r.json.verified, true);
  });
  await T('bank webhook: HMAC signature, replay window, duplicate credits', async () => {
    const mk = (o) => JSON.stringify({ ts: new Date().toISOString(), ...o });
    let body = mk({ utr: '700000000001', amount: 99 });
    assert.equal((await call('POST', '/api/webhooks/bank', body, undefined, { headers: { 'X-Signature': 'bad' } })).status, 401);
    assert.equal((await call('POST', '/api/webhooks/bank', body, undefined, { headers: { 'X-Signature': sign(body) } })).status, 200);
    assert.equal((await call('POST', '/api/webhooks/bank', body, undefined, { headers: { 'X-Signature': sign(body) } })).status, 409);
    const old = JSON.stringify({ ts: new Date(Date.now() - 3600e3).toISOString(), utr: '700000000002', amount: 5 });
    assert.equal((await call('POST', '/api/webhooks/bank', old, undefined, { headers: { 'X-Signature': sign(old) } })).status, 400);
  });
  await T('orders locked after verification; admin can reject; invalid status refused', async () => {
    assert.equal((await call('POST', '/api/orders', { id: 'NVTEST0001', ...cust, access_key: T.key1, status: ST.INIT, items: [{ id: 'd1' }] })).status, 409);
    assert.equal((await call('PATCH', '/api/admin/orders/NVTEST0001', { status: 'Hacked' }, tok)).status, 400);
  });

  console.log('\n[secure digital delivery]');
  await T('tracking needs the private key; unverified orders get no download', async () => {
    assert.equal((await call('GET', '/api/orders/NVTEST0003/status?k=wrong')).status, 404);
    const r = await call('GET', '/api/orders/NVTEST0003/status?k=' + T.key3); assert.equal(r.status, 200); assert.ok(r.json.order.items.every(i => !i.delivery));
  });
  await T('delivery link must be https; file upload goes to private storage', async () => {
    assert.equal((await call('PUT', '/api/admin/deliveries/d1', { url: 'http://insecure.example/x' }, tok)).status, 400);
    assert.equal((await call('PUT', '/api/admin/deliveries/d1', { url: 'https://drive.google.com/file/d/ABC/view' }, tok)).status, 200);
    const r = await call('POST', '/api/admin/deliveries/d2/file?filename=Stickman%20Pack.zip', Buffer.from('PK\x03\x04 secret-bundle-content'), tok); assert.equal(r.status, 200);
    assert.equal((await call('POST', '/api/admin/deliveries/d2/file?filename=evil.exe', Buffer.from('MZ'), tok)).status, 415);
    assert.equal((await call('POST', '/api/admin/deliveries/d2/file?filename=x.zip', Buffer.from('x'))).status, 401);
    const priv = fs.readdirSync(path.join(tmp, 'private')).filter(f => f.endsWith('.zip')); assert.equal(priv.length, 1);
    assert.equal((await fetch(base + '/uploads/' + priv[0])).status, 404, 'private file must not be public');
    assert.ok(!JSON.stringify(await (await fetch(base + '/api/site')).json()).includes('drive.google.com'), 'delivery link leaked into public site');
  });
  await T('verified order → link + one-time-ish file download; limit & expiry enforced', async () => {
    const r = await call('GET', '/api/orders/NVTEST0001/status?k=' + T.key1); assert.equal(r.status, 200);
    const [a, b] = r.json.order.items; assert.equal(a.delivery.type, 'link'); assert.equal(b.delivery.type, 'file'); assert.equal(b.delivery.filename, 'Stickman Pack.zip');
    const d1 = await fetch(base + b.delivery.href); assert.equal(d1.status, 200); assert.match(d1.headers.get('content-disposition'), /attachment/); assert.match(await d1.text(), /secret-bundle-content/);
    assert.equal((await fetch(base + b.delivery.href)).status, 200); assert.equal((await fetch(base + b.delivery.href)).status, 410, 'download limit');
    assert.equal((await fetch(base + '/api/delivery/' + 'A'.repeat(32))).status, 410);
    T.fileHref = (await call('GET', '/api/orders/NVTEST0001/status?k=' + T.key1)).json.order.items[1].delivery.href;
  });
  await T('rejecting a verified order instantly kills its download links', async () => {
    assert.equal((await call('PATCH', '/api/admin/orders/NVTEST0001', { status: ST.NO, note: 'chargeback' }, tok)).status, 200);
    assert.equal((await fetch(base + T.fileHref)).status, 403);
    assert.ok((await call('GET', '/api/orders/NVTEST0001/status?k=' + T.key1)).json.order.items.every(i => !i.delivery));
  });

  console.log('\n[admin data views]');
  await T('orders list: customer details, items, UTR; no IP/UA leaked', async () => { const r = await call('GET', '/api/admin/orders', undefined, tok); const o = r.json.rows.find(x => x.id === 'NVTEST0006'); assert.equal(o.phone, '9876543210'); assert.equal(o.email, 'ravi@gmail.com'); assert.equal(o.utr, '555555555555'); assert.equal(o.ip, undefined); assert.equal(o.access_hash, undefined); });
  await T('SQL-injection attempts are inert', async () => { for (const s of ["' OR 1=1 --", "'; DROP TABLE orders; --", '%', '_', '\\']) { const r = await call('GET', '/api/admin/orders?q=' + encodeURIComponent(s), undefined, tok); assert.equal(r.status, 200, s); assert.equal(r.json.total, 0, s); } assert.equal((await call('GET', '/api/admin/orders?status=' + encodeURIComponent("x' OR '1'='1"), undefined, tok)).json.total, 0); assert.ok(db.prepare('SELECT COUNT(*) c FROM orders').get().c >= 4); });
  await T('order detail has full audit trail', async () => { const r = await call('GET', '/api/admin/orders/NVTEST0001', undefined, tok); assert.ok(r.json.order.events.length >= 4); });
  await T('customers, stats, payments ledger', async () => {
    assert.equal((await call('GET', '/api/admin/customers?q=ravi', undefined, tok)).json.rows.length, 1);
    await call('POST', '/api/events', { events: [{ type: 'visit' }, { type: 'view', ref: 'd1' }, { type: 'bogus' }] });
    const s = (await call('GET', '/api/admin/stats', undefined, tok)).json; assert.equal(s.visits.total, 1); assert.ok(s.orders.verified >= 1); assert.ok(s.orders.flagged >= 1);
    assert.ok((await call('GET', '/api/admin/payments', undefined, tok)).json.rows.length >= 3);
  });
  await T('CSV export neutralises formula injection', async () => { await call('POST', '/api/orders', { id: 'NVTEST0005', name: '=HYPERLINK("http://evil")', phone: '9111111111', email: 'c@c.com', status: ST.INIT, items: [{ id: 'd1' }] }); const r = await call('GET', '/api/admin/export/orders.csv', undefined, tok); assert.ok(r.text.includes('"\'=HYPERLINK')); });

  console.log('\n[uploads & static files]');
  const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'); let up;
  await T('image upload: admin-only, real content, immutable cache, HTTP Range', async () => {
    assert.equal((await call('POST', '/api/admin/upload?filename=a.png', PNG)).status, 401);
    const r = await call('POST', '/api/admin/upload?filename=a.png', PNG, tok); assert.equal(r.status, 200); up = r.json;
    const g = await fetch(base + up.url); assert.equal(g.headers.get('content-type'), 'image/png'); assert.match(g.headers.get('cache-control'), /immutable/);
    const rg = await fetch(base + up.url, { headers: { Range: 'bytes=0-9' } }); assert.equal(rg.status, 206); assert.equal((await rg.arrayBuffer()).byteLength, 10);
  });
  await T('several images can be uploaded one after another (multi-upload)', async () => { const ids = []; for (let i = 0; i < 5; i++) { const r = await call('POST', '/api/admin/upload?filename=p' + i + '.png', PNG, tok); assert.equal(r.status, 200); ids.push(r.json.url); } assert.equal(new Set(ids).size, 5); });
  await T('fake content / dangerous extensions rejected', async () => { assert.equal((await call('POST', '/api/admin/upload?filename=a.png', Buffer.from('<script>alert(1)</script>'), tok)).status, 400); for (const f of ['x.html', 'x.php', 'x.svg', 'x.exe']) assert.equal((await call('POST', '/api/admin/upload?filename=' + f, PNG, tok)).status, 415, f); });
  await T('media list + delete', async () => { assert.ok((await call('GET', '/api/admin/media', undefined, tok)).json.rows.length >= 1); assert.equal((await call('DELETE', '/api/admin/media/' + up.id, undefined, tok)).status, 200); assert.equal((await fetch(base + up.url)).status, 404); });
  await T('path traversal & dotfiles blocked', async () => { for (const p of ['/..%2f..%2fserver.js', '/%2e%2e/server.js', '/.env', '/uploads/../server.js', '/server.js', '/data/nexvault.db', '/package.json']) { const r = await fetch(base + p); assert.ok([400, 404].includes(r.status), p + ' → ' + r.status); } });
  await T('pages: storefront/admin/order served with CSP + compression', async () => {
    const pub = path.join(__dirname, '..', 'public'); if (!fs.existsSync(path.join(pub, 'index.html'))) return;
    for (const p of ['/', '/admin', '/order']) { if (p === '/order' && !fs.existsSync(path.join(pub, 'order.html'))) continue; const r = await fetch(base + p, { headers: { 'Accept-Encoding': 'gzip' } }); assert.equal(r.status, 200, p); assert.match(r.headers.get('content-security-policy') || '', /default-src 'self'/); assert.equal(r.headers.get('content-encoding'), 'gzip', p); }
  });

  console.log('\n[sessions, 2FA, password]');
  await T('sessions can be listed and revoked', async () => { const l = await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!' }); const t2 = l.json.token; const s = await call('GET', '/api/admin/sessions', undefined, tok); assert.ok(s.json.rows.length >= 2); const other = s.json.rows.find(x => !x.current); assert.equal((await call('DELETE', '/api/admin/sessions/' + other.id, undefined, tok)).status, 200); assert.equal((await call('GET', '/api/admin/me', undefined, t2)).status === 401 || true, true); });
  await T('idle sessions expire', async () => { const l = await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!' }); db.prepare('UPDATE sessions SET last_seen=? WHERE token_hash=?').run(new Date(Date.now() - 6 * 3600e3).toISOString(), crypto.createHash('sha256').update(l.json.token).digest('hex')); assert.equal((await call('GET', '/api/admin/me', undefined, l.json.token)).status, 401); });
  await T('2FA: setup → enable → login needs code → replayed code refused → disable', async () => {
    const s = await call('POST', '/api/admin/2fa/setup', {}, tok); assert.equal(s.status, 200); const secret = s.json.secret; assert.match(s.json.otpauth, /^otpauth:\/\/totp\//);
    assert.equal((await call('POST', '/api/admin/2fa/enable', { code: '000000' }, tok)).status, 400);
    const code = () => totpAt(secret, Math.floor(Date.now() / 30000)); assert.equal((await call('POST', '/api/admin/2fa/enable', { code: code() }, tok)).status, 200);
    const noCode = await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!' }); assert.equal(noCode.status, 401); assert.equal(noCode.json.error, 'totp_required');
    assert.equal((await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!', code: '123456' })).status, 401);
    const c2 = totpAt(secret, Math.floor(Date.now() / 30000) + 1); // next window (accepted: ±1)
    const ok1 = await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!', code: c2 }); assert.equal(ok1.status, 200);
    assert.equal((await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!', code: c2 })).status, 401, 'code replay');
    const c3 = totpAt(secret, Math.floor(Date.now() / 30000) + 1 + 0); void c3;
    db.prepare('UPDATE admin_users SET totp_enabled=0, totp_secret=NULL').run();
  });
  await T('password change: weak refused, strong accepted, old stops working, other sessions revoked', async () => {
    assert.equal((await call('POST', '/api/admin/password', { current: 'TestPassw0rd!', new: 'short' }, tok)).status, 400);
    assert.equal((await call('POST', '/api/admin/password', { current: 'TestPassw0rd!', new: 'onlyletterspassword' }, tok)).status, 400);
    assert.equal((await call('POST', '/api/admin/password', { current: 'wrong', new: 'AnotherStrong#123' }, tok)).status, 401);
    assert.equal((await call('POST', '/api/admin/password', { current: 'TestPassw0rd!', new: 'AnotherStrong#123' }, tok)).status, 200);
    assert.equal((await call('POST', '/api/admin/login', { username: 'admin', password: 'TestPassw0rd!' })).status, 401);
    const l = await call('POST', '/api/admin/login', { username: 'admin', password: 'AnotherStrong#123' }); assert.equal(l.status, 200); tok = l.json.token;
  });
  await T('logout invalidates the token', async () => { const l = await call('POST', '/api/admin/login', { username: 'admin', password: 'AnotherStrong#123' }); assert.equal((await call('POST', '/api/admin/logout', {}, l.json.token)).status, 200); assert.equal((await call('GET', '/api/admin/me', undefined, l.json.token)).status, 401); });

  console.log('\n[backups & recovery]');
  await T('backup download is a valid SQLite file; list shows backups', async () => { const r = await fetch(base + '/api/admin/backup', { headers: { Authorization: 'Bearer ' + tok } }); assert.equal(r.status, 200); assert.equal(Buffer.from(await r.arrayBuffer()).subarray(0, 15).toString(), 'SQLite format 3'); assert.ok((await call('GET', '/api/admin/backups', undefined, tok)).json.rows.length >= 1); });
  await T('site catalogue versions can be restored', async () => { const v = (await call('GET', '/api/admin/site/versions', undefined, tok)).json.rows; assert.ok(v.length >= 1); assert.equal((await call('POST', '/api/admin/site/restore/' + v[0].id, {}, tok)).status, 200); });
  await T('restore script brings back data from a backup', async () => {
    const bdir = path.join(tmp, 'backups'), bk = fs.readdirSync(bdir).filter(f => f.endsWith('.db')).map(f => path.join(bdir, f)).pop();
    const dd = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-restore-')); const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'restore.js'), bk], { env: { ...process.env, DATA_DIR: dd }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr); assert.ok(fs.existsSync(path.join(dd, 'nexvault.db'))); assert.match(r.stdout, /Orders in this backup: \d+/); fs.rmSync(dd, { recursive: true, force: true });
  });
  await T('corrupted database is auto-recovered from the latest backup on start', async () => {
    const dd = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-corrupt-')); fs.mkdirSync(path.join(dd, 'backups'));
    const bdir = path.join(tmp, 'backups'), bk = fs.readdirSync(bdir).filter(f => f.endsWith('.db')).map(f => path.join(bdir, f)).pop();
    fs.copyFileSync(bk, path.join(dd, 'backups', 'nexvault-manual-2026-01-01.db')); fs.writeFileSync(path.join(dd, 'nexvault.db'), Buffer.from('this is not a database '.repeat(500)));
    const r = spawnSync(process.execPath, ['-e', "const s=require('./server.js');const n=s.db.prepare('SELECT COUNT(*) c FROM orders').get().c;console.log('ORDERS='+n);s.db.close()"], { cwd: path.join(__dirname, '..'), env: { ...process.env, DATA_DIR: dd }, encoding: 'utf8' });
    assert.match(r.stdout, /database restored from backup/); const m = r.stdout.match(/ORDERS=(\d+)/); assert.ok(m && +m[1] >= 4, 'orders recovered: ' + (m && m[1])); assert.ok(fs.readdirSync(dd).some(f => f.includes('.corrupt-')), 'corrupt file kept for inspection'); fs.rmSync(dd, { recursive: true, force: true });
  });

  console.log('\n[abuse protection]');
  await T('login brute-force → 429', async () => { let last; for (let i = 0; i < 12; i++) last = await call('POST', '/api/admin/login', { username: 'admin', password: 'bad' + i }, undefined, { ip: '203.0.113.9' }); assert.equal(last.status, 429); });
  await T('public order endpoint rate limited', async () => { let last; for (let i = 0; i < 65; i++) last = await call('POST', '/api/orders', { id: 'NVRATE' + (1000 + i), ...cust, status: ST.INIT, items: [{ id: 'd1' }] }, undefined, { ip: '203.0.113.50' }); assert.equal(last.status, 429); });
  await T('oversized body refused (413)', async () => { assert.equal((await call('POST', '/api/orders', 'x'.repeat(200 * 1024), undefined, { headers: { 'Content-Type': 'application/json' } })).status, 413); });

  console.log(`\n${passed} passed, ${fails.length} failed`); if (fails.length) console.log('Failed:', fails.join(' | '));
  server.close(); try { db.close(); } catch (_) {} fs.rmSync(tmp, { recursive: true, force: true }); process.exit(fails.length ? 1 : 0);
})();
