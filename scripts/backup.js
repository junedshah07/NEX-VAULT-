'use strict';
// Manual backup:  npm run backup        (safe while the server is running)
process.env.__NV_SCRIPT = '1';
const path = require('node:path'), fs = require('node:fs');
require('node:module'); // keep Node >=22.13 check in server.js
const { makeBackup, db, CFG } = require('../server.js');
try { const f = makeBackup('manual'); console.log('Backup created:', f, `(${(fs.statSync(f).size / 1024).toFixed(0)} KB)`); db.close(); process.exit(0); }
catch (e) { console.error('Backup failed:', e.message); process.exit(1); }
