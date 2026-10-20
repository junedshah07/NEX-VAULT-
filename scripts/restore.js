'use strict';
// Restore from a backup file:   npm run restore -- data/backups/nexvault-auto-....db
// STOP the server first. The current database is kept as *.pre-restore-<time>.
const fs = require('node:fs'), path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const src = process.argv[2];
if (!src || !fs.existsSync(src)) { console.error('Usage: npm run restore -- <backup-file.db>\nBackups live in ' + path.resolve(process.env.BACKUP_DIR || path.join(process.env.DATA_DIR || path.join(__dirname, '..', 'data'), 'backups'))); process.exit(1); }
const dataDir = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data')), dest = path.join(dataDir, 'nexvault.db');
const t = new DatabaseSync(path.resolve(src), { readOnly: true });
const r = t.prepare('PRAGMA integrity_check').get().integrity_check;
const orders = t.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE name='orders'").get().c ? t.prepare('SELECT COUNT(*) c FROM orders').get().c : 0;
t.close();
if (r !== 'ok') { console.error('Backup file is damaged (' + r + '). Pick another one.'); process.exit(1); }
fs.mkdirSync(dataDir, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
for (const s of ['', '-wal', '-shm']) if (fs.existsSync(dest + s)) fs.renameSync(dest + s, `${dest}.pre-restore-${stamp}${s}`);
fs.copyFileSync(path.resolve(src), dest);
console.log(`Restored ${path.basename(src)} → ${dest}\nOrders in this backup: ${orders}\nPrevious database saved as nexvault.db.pre-restore-${stamp}\nNow start the server again.`);
