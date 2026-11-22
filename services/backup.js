// services/backup.js — copies of the live SQLite DB on the same volume (phase 0).
//
//   <dir>/grand_furniture-YYYY-MM-DD.db              one per Cairo day, the newest 7 kept
//   <dir>/grand_furniture-preboot-<BUILD_VERSION>.db  the first boot of each version,
//                                                    BEFORE its migrations; the newest 3 kept
// <dir> = BACKUP_DIR, else «backups» next to DB_PATH (/data/backups on Railway).
//
// When:
//   • boot, before anything opens the DB (so before every migration): the
//     pre-boot copy of this version if it doesn't exist yet (a crash-restart
//     loop never overwrites the first, good copy), and today's daily copy if
//     it doesn't exist yet. Synchronous (VACUUM INTO on a short-lived
//     connection), so it is done before server.js's migrations run.
//   • every day at 04:00 Cairo (checked every 10 minutes, so a sleep or a
//     restart over 04:00 catches up): today's daily copy, if missing, with the
//     online db.backup() (async, never blocks requests).
// Never fails the boot or a request: an error is logged (no path, no data)
// and shown as backup.last_error on /health. A copy is skipped when the
// volume's free space after it would drop under twice the DB's size.
// It is written under a .partial name and renamed, so a half copy is never
// counted or rotated in. The demo DB is never copied: the sandbox is removed
// (2026-11-22; db.js deletes its file at boot) and isDemoPath() refuses its
// file here too, so a copy of it can never land in the backups.
'use strict';

const fs       = require('fs');
const path     = require('path');
const Database = require('better-sqlite3');

const DAILY_KEEP   = 7;
const PREBOOT_KEEP = 3;
const DAILY_HOUR   = 4;          // Cairo
const DAILY_RE     = /^grand_furniture-(\d{4}-\d{2}-\d{2})\.db$/;
const PREBOOT_RE   = /^grand_furniture-preboot-[A-Za-z0-9._-]+\.db$/;

const state = { last_backup_at: null, last_error: null, last_error_at: null, count: 0, skipped_low_space: 0 };

const _fmt = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit',
  day: '2-digit', hour: '2-digit', hourCycle: 'h23' });
function cairoNow(d = new Date()) {
  const p = Object.fromEntries(_fmt.formatToParts(d).map(x => [x.type, x.value]));
  return { day: `${p.year}-${p.month}-${p.day}`, hour: Number(p.hour) };
}

// The old sandbox's file (grand_furniture_demo.db) — never a backup source.
function isDemoPath(p) { return /_demo\.db$/i.test(path.basename(String(p || ''))); }

function backupDir(dbPath) {
  return process.env.BACKUP_DIR || path.join(path.dirname(dbPath), 'backups');
}
function safeVersion(v) { return String(v || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80); }

function listBackups(dir) {
  let names = [];
  try { names = fs.readdirSync(dir); } catch (_) { return { daily: [], preboot: [] }; }
  const stat = (n) => { try { return fs.statSync(path.join(dir, n)); } catch (_) { return null; } };
  const daily   = names.filter(n => DAILY_RE.test(n)).sort();                     // by date in the name
  const preboot = names.filter(n => PREBOOT_RE.test(n))
    .map(n => ({ n, t: (stat(n) || {}).mtimeMs || 0 })).sort((a, b) => a.t - b.t).map(x => x.n);
  return { daily, preboot };
}

function refreshState(dir) {
  const { daily, preboot } = listBackups(dir);
  state.count = daily.length + preboot.length;
  let newest = 0;
  for (const n of [...daily, ...preboot]) {
    try { newest = Math.max(newest, fs.statSync(path.join(dir, n)).mtimeMs); } catch (_) {}
  }
  state.last_backup_at = newest ? new Date(newest).toISOString() : null;
}

function rotate(dir) {
  const { daily, preboot } = listBackups(dir);
  const drop = [...daily.slice(0, Math.max(0, daily.length - DAILY_KEEP)),
                ...preboot.slice(0, Math.max(0, preboot.length - PREBOOT_KEEP))];
  for (const n of drop) { try { fs.rmSync(path.join(dir, n)); } catch (_) {} }
  // A .partial left by a crash mid-copy.
  try {
    for (const n of fs.readdirSync(dir)) if (n.endsWith('.partial')) { try { fs.rmSync(path.join(dir, n)); } catch (_) {} }
  } catch (_) {}
}

function fail(where, e) {
  state.last_error = `${where}: ${String((e && e.code) || (e && e.message) || e).slice(0, 80)}`;
  state.last_error_at = new Date().toISOString();
  console.error(`[backup] ${where} failed — ${(e && e.code) || 'error'}`);
}

// Room for one more copy: free space after it ≥ 2 × the DB's size.
function hasRoom(dir, dbPath) {
  try {
    if (typeof fs.statfsSync !== 'function') return true;
    const size = dbSize(dbPath);
    const s = fs.statfsSync(dir);
    const free = Number(s.bavail) * Number(s.bsize);
    return free - size >= 2 * size;
  } catch (_) { return true; }
}
function dbSize(dbPath) {
  let n = 0;
  for (const suf of ['', '-wal']) { try { n += fs.statSync(dbPath + suf).size; } catch (_) {} }
  return n;
}

// Synchronous copy through a short-lived connection (boot only).
function vacuumInto(dbPath, dest) {
  const tmp = dest + '.partial';
  try { fs.rmSync(tmp, { force: true }); } catch (_) {}
  const src = new Database(dbPath, { fileMustExist: true });
  try {
    src.pragma('busy_timeout = 5000');
    src.prepare('VACUUM INTO ?').run(tmp);
  } finally { try { src.close(); } catch (_) {} }
  fs.renameSync(tmp, dest);
}

/**
 * Boot: call before anything opens the DB. Never throws.
 * @returns {{preboot:boolean, daily:boolean}} what was written
 */
function bootBackup({ dbPath, version, now = new Date() }) {
  const out = { preboot: false, daily: false };
  try {
    if (!dbPath || isDemoPath(dbPath) || !fs.existsSync(dbPath)) return out;   // a fresh install: nothing to keep
    const dir = backupDir(dbPath);
    fs.mkdirSync(dir, { recursive: true });
    const pre = path.join(dir, `grand_furniture-preboot-${safeVersion(version)}.db`);
    if (!fs.existsSync(pre)) {
      if (hasRoom(dir, dbPath)) { vacuumInto(dbPath, pre); out.preboot = true; }
      else state.skipped_low_space++;
    }
    const daily = path.join(dir, `grand_furniture-${cairoNow(now).day}.db`);
    if (!fs.existsSync(daily)) {
      if (hasRoom(dir, dbPath)) { vacuumInto(dbPath, daily); out.daily = true; }
      else state.skipped_low_space++;
    }
    rotate(dir);
    refreshState(dir);
    if (out.preboot || out.daily) console.log(`💾 Backup at boot: preboot=${out.preboot} daily=${out.daily} (${state.count} kept)`);
  } catch (e) { fail('boot', e); }
  return out;
}

let running = false;
/**
 * The day's copy with the online backup API. Never rejects.
 * @param {object} liveDb   the app's live better-sqlite3 handle
 */
async function dailyBackup({ liveDb, dbPath, now = new Date(), force = false }) {
  if (running) return false;
  running = true;
  try {
    const c = cairoNow(now);
    if (!force && c.hour < DAILY_HOUR) return false;
    if (isDemoPath(dbPath)) return false;
    const dir = backupDir(dbPath);
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(dir, `grand_furniture-${c.day}.db`);
    if (fs.existsSync(dest)) return false;
    if (!hasRoom(dir, dbPath)) { state.skipped_low_space++; return false; }
    const tmp = dest + '.partial';
    try { fs.rmSync(tmp, { force: true }); } catch (_) {}
    await liveDb.backup(tmp);
    fs.renameSync(tmp, dest);
    rotate(dir);
    refreshState(dir);
    console.log(`💾 Daily backup written (${state.count} kept)`);
    return true;
  } catch (e) { fail('daily', e); return false; }
  finally { running = false; }
}

function startSchedule({ getLiveDb, dbPath, everyMs = 10 * 60 * 1000 }) {
  const tick = () => { dailyBackup({ liveDb: getLiveDb(), dbPath }).catch(() => {}); };
  const t = setInterval(tick, everyMs);
  if (t.unref) t.unref();
  const first = setTimeout(tick, 60 * 1000);
  if (first.unref) first.unref();
  try { refreshState(backupDir(dbPath)); } catch (_) {}
  return t;
}

function snapshot() { return { ...state }; }

module.exports = { bootBackup, dailyBackup, startSchedule, snapshot, backupDir, cairoNow, isDemoPath, DAILY_KEEP, PREBOOT_KEEP, _rotate: rotate };
