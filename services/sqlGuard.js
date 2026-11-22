// services/sqlGuard.js — what model-written SQL may read (phase 0).
//
// Used by the MCP run_select_sql (server.js + mcp-server.js) and the admin AI
// chat's run_select_sql. Three locks, each enough on its own for writes:
//   1. text: ONE statement that starts with SELECT or WITH;
//   2. the connection: opened readonly + PRAGMA query_only (db.getReadonlyDb);
//      better-sqlite3 also reports stmt.reader — only readers run;
//   3. the tables: an explicit ALLOWLIST, checked on SQLite's own compiled
//      program (EXPLAIN), not on the text — so aliases, sub-queries, CTEs,
//      views, comments and quoting can't hide a table. Every cursor the
//      statement opens (OpenRead → root page) is mapped back to its table; a
//      table outside the list, the schema table (sqlite_master), a temp or
//      attached database, or any virtual table (pragma_* functions) refuses
//      the statement. Columns are checked too: users.password_hash can't be
//      read, filtered on or sorted by.
//
// Not allowed, ever: settings (API keys, webhook / jwt secret), the audit log
// (system_audit_log), the one-time migration backup, sqlite_* tables, and any
// table added later until it is put on this list on purpose.

const ALLOWED_TABLES = new Set([
  'lead_profiles', 'lead_phones', 'events', 'lead_visits', 'visit_checkins',
  'branch_customer_followups', 'followup_log', 'revisit_followups', 'follow_up_state',
  'purchases', 'purchase_items', 'products', 'product_categories',
  'sales_targets', 'tasks', 'messages_sent', 'notifications',
  'achievement_badges', 'ai_briefs', 'users',
]);

// table → columns no reader may touch
const DENIED_COLUMNS = {
  users: new Set(['password_hash']),
};

const REFUSED_AR = 'مرفوض — الأداة دي للقراءة فقط: جملة SELECT واحدة، على جداول الشغل بس (الإعدادات وسجل التدقيق وكلمات السر ممنوعين).';

function textCheck(query) {
  let q = String(query || '').trim();
  q = q.replace(/;\s*$/, '');
  if (!q) return { ok: false, reason: 'empty' };
  if (q.includes(';')) return { ok: false, reason: 'multiple_statements' };
  if (!/^(select|with)\b/i.test(q)) return { ok: false, reason: 'not_select' };
  if (/\b(insert|update|delete|drop|alter|create|replace|attach|detach|vacuum|pragma|trigger|reindex|analyze)\b/i.test(q)) {
    return { ok: false, reason: 'write_keyword' };
  }
  return { ok: true, sql: q };
}

// root page → { table, kind:'table'|'index', index? } for the main database.
function schemaMap(db) {
  const map = new Map();
  map.set(1, { table: 'sqlite_master', kind: 'table' });
  for (const r of db.prepare(`SELECT type, name, tbl_name, rootpage FROM sqlite_master WHERE rootpage > 0`).all()) {
    map.set(r.rootpage, { table: r.tbl_name, kind: r.type === 'index' ? 'index' : 'table', index: r.type === 'index' ? r.name : null });
  }
  return map;
}

function indexColumns(db, indexName, cache) {
  if (cache.has(indexName)) return cache.get(indexName);
  // index_xinfo: seqno order = the index record's column order; cid -1 = rowid.
  const cols = db.prepare(`SELECT seqno, cid, name FROM pragma_index_xinfo(?) ORDER BY seqno`).all(indexName)
    .map(r => r.name);
  cache.set(indexName, cols);
  return cols;
}

function tableColumns(db, table, cache) {
  const key = 't:' + table;
  if (cache.has(key)) return cache.get(key);
  const cols = db.prepare(`SELECT cid, name FROM pragma_table_info(?) ORDER BY cid`).all(table).map(r => r.name);
  cache.set(key, cols);
  return cols;
}

/**
 * Checks one SELECT against the allowlist on the given (read-only) handle.
 * @returns {{ok:true, sql:string}|{ok:false, reason:string, table?:string}}
 */
function checkSelect(db, query) {
  const t = textCheck(query);
  if (!t.ok) return t;
  let stmt;
  try { stmt = db.prepare(t.sql); } catch (e) { return { ok: false, reason: 'prepare_failed', error: e.message }; }
  if (!stmt.reader) return { ok: false, reason: 'not_reader' };

  let program;
  try { program = db.prepare('EXPLAIN ' + t.sql).all(); }
  catch (e) { return { ok: false, reason: 'explain_failed', error: e.message }; }

  const roots = schemaMap(db);
  const cache = new Map();
  const cursors = new Map();          // cursor → { table, cols }
  for (const op of program) {
    const code = op.opcode;
    if (code === 'VOpen' || code === 'VFilter' || code === 'VColumn') return { ok: false, reason: 'virtual_table' };
    if (code === 'OpenWrite' || code === 'Destroy' || code === 'Clear' || code === 'CreateBtree' || code === 'ParseSchema') {
      return { ok: false, reason: 'write_op' };
    }
    if (code === 'OpenRead' || code === 'ReopenIdx') {
      if (op.p3 !== 0) return { ok: false, reason: 'other_database' };
      const info = roots.get(op.p2);
      if (!info) return { ok: false, reason: 'unknown_root' };
      if (!ALLOWED_TABLES.has(info.table)) return { ok: false, reason: 'table_not_allowed', table: info.table };
      const cols = info.kind === 'index' ? indexColumns(db, info.index, cache) : tableColumns(db, info.table, cache);
      cursors.set(op.p1, { table: info.table, cols });
    }
    if (code === 'OpenDup') {
      const src = cursors.get(op.p2);
      if (src) cursors.set(op.p1, src);
    }
  }
  for (const op of program) {
    if (op.opcode !== 'Column') continue;
    const c = cursors.get(op.p1);
    if (!c) continue;                  // ephemeral / sorter / pseudo cursor: holds already-checked values
    const denied = DENIED_COLUMNS[c.table];
    if (!denied) continue;
    const name = c.cols[op.p2];
    if (name === undefined || denied.has(name)) return { ok: false, reason: 'column_not_allowed', table: c.table };
  }
  return { ok: true, sql: t.sql, stmt };
}

/**
 * Runs a checked SELECT; never throws. limit caps the rows returned.
 * @returns {{row_count:number, rows:object[]}|{error:string, reason:string}}
 */
function runGuardedSelect(db, query, limit = 200) {
  const c = checkSelect(db, query);
  if (!c.ok) return { error: REFUSED_AR, reason: c.reason };
  try {
    const rows = c.stmt.all();
    return { row_count: rows.length, rows: rows.slice(0, limit) };
  } catch (e) {
    return { error: 'خطأ في الاستعلام: ' + e.message, reason: 'run_failed' };
  }
}

// The text-only check the old isSafeSelectSql made (kept for its callers).
function isSafeSelectText(query) { return textCheck(query).ok; }

module.exports = { ALLOWED_TABLES, DENIED_COLUMNS, checkSelect, runGuardedSelect, isSafeSelectText, REFUSED_AR };
