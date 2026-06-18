#!/usr/bin/env node
/**
 * db-vacuum.js — reclaim unused SQLite disk space (manual maintenance).
 *
 * Checkpoints the WAL into the main DB, then runs VACUUM to defragment and
 * release free pages back to the filesystem. Run on the Railway volume when
 * the disk is filling up:
 *
 *     railway ssh "node /app/scripts/db-vacuum.js"
 *
 * Safe to run while the app is up, but VACUUM takes a brief exclusive lock —
 * prefer a low-traffic moment. Targets the LIVE db by default; pass paths to
 * override. Never throws fatally on one db so the other still runs.
 */
const Database = require('better-sqlite3');
const fs = require('fs');

const targets = process.argv.slice(2);
if (targets.length === 0) {
  targets.push('/data/grand_furniture.db');           // live
  if (fs.existsSync('/data/grand_furniture_demo.db'))
    targets.push('/data/grand_furniture_demo.db');    // demo (if present)
}

const mb = (p) => { try { return (fs.statSync(p).size / 1048576).toFixed(1) + 'M'; } catch { return '?'; } };

for (const path of targets) {
  try {
    if (!fs.existsSync(path)) { console.log(`skip (missing): ${path}`); continue; }
    const before = mb(path);
    const db = new Database(path);
    db.pragma('wal_checkpoint(TRUNCATE)'); // fold WAL into the main file first
    db.exec('VACUUM');                     // defragment + free pages → filesystem
    db.pragma('wal_checkpoint(TRUNCATE)'); // tidy the WAL VACUUM just produced
    db.close();
    console.log(`✓ vacuumed ${path}: ${before} → ${mb(path)}`);
  } catch (err) {
    console.error(`✗ ${path}: ${err.message}`);
  }
}
console.log('done.');
