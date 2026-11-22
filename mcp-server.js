#!/usr/bin/env node
/**
 * mcp-server.js — Model Context Protocol server for the Grand Furniture CRM.
 *
 * A COMPLETELY STANDALONE layer: it does not import or modify server.js or
 * db.js and does not touch any frontend code. It opens its OWN connection to
 * the production database.
 *
 * MODE: READ ONLY since phase 0 (2026-11-22). The DB is opened readonly +
 * PRAGMA query_only; run_select_sql goes through services/sqlGuard.js (a table
 * allowlist checked on SQLite's compiled program: settings, the audit log,
 * sqlite_master and users.password_hash are refused); execute_write_sql
 * answers that it is off and runs nothing (removal: the owner's call).
 *
 * Transport: stdio (for Claude Desktop). NOTE: stdout is reserved for the
 * JSON-RPC protocol — this file only ever logs to stderr.
 */
const path     = require('path');
const Database = require('better-sqlite3');
const { z }    = require('zod');
const { McpServer }            = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const sqlGuard = require('./services/sqlGuard');

// ── DB connection — READ ONLY (phase 0) ──────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'grand_furniture.db');
let db;
try {
  db = new Database(DB_PATH, { fileMustExist: true, readonly: true });
  db.pragma('query_only = ON');
} catch (e) {
  console.error(`[mcp] failed to open DB at ${DB_PATH}: ${e.message}`);
  process.exit(1);
}

const currentMonth = () => new Date().toISOString().slice(0, 7); // YYYY-MM
const ok   = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
const fail = (msg) => ({ content: [{ type: 'text', text: 'خطأ: ' + msg }], isError: true });

// ── MCP server ───────────────────────────────────────────────────────────────
const server = new McpServer({ name: 'grand-furniture-crm', version: '1.0.0' });

// Tool A — branch KPIs ─────────────────────────────────────────────────────────
server.registerTool(
  'get_branch_kpis',
  {
    description:
      'مؤشرات أداء فرع: إجمالي المبيعات، عدد الزيارات، والمستهدف لشهر معيّن. ' +
      'لو الفرع غير محدد بترجع أرقام كل الفروع مجمّعة.',
    inputSchema: {
      branch:       z.string().optional().describe('اسم/مُعرّف الفرع — اتركه فارغاً لكل الفروع'),
      target_month: z.string().optional().describe('الشهر بصيغة YYYY-MM (افتراضي: الشهر الحالي)'),
    },
  },
  async ({ branch, target_month }) => {
    try {
      const month = (target_month && /^\d{4}-\d{2}$/.test(target_month))
        ? target_month : currentMonth();

      let revWhere = `strftime('%Y-%m', created_at) = ?`;
      const revParams = [month];
      if (branch) { revWhere += ' AND branch = ?'; revParams.push(branch); }
      const revenue = db.prepare(
        `SELECT COALESCE(SUM(price), 0) AS r FROM purchases WHERE ${revWhere}`
      ).get(...revParams).r;

      let visWhere = `strftime('%Y-%m', visited_at) = ?`;
      const visParams = [month];
      if (branch) { visWhere += ' AND branch = ?'; visParams.push(branch); }
      const visits = db.prepare(
        `SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits WHERE ${visWhere}`
      ).get(...visParams).n;

      let target;
      if (branch) {
        const row = db.prepare(
          `SELECT target_amount FROM sales_targets
           WHERE scope_type = 'branch' AND scope_name = ? AND target_month = ?`
        ).get(branch, month);
        target = row ? Number(row.target_amount) || 0 : 0;
      } else {
        target = db.prepare(
          `SELECT COALESCE(SUM(target_amount), 0) AS t FROM sales_targets
           WHERE scope_type = 'branch' AND target_month = ?`
        ).get(month).t || 0;
      }

      return ok({
        branch: branch || 'كل الفروع',
        target_month: month,
        total_revenue: revenue,
        visit_count: visits,
        target_amount: target,
        target_achievement_pct: target > 0 ? Math.round((revenue / target) * 100) : 0,
      });
    } catch (e) {
      return fail(e.message);
    }
  }
);

// Tool B — leads by status (for the AI to identify rows before editing) ───────
server.registerTool(
  'get_leads_by_status',
  {
    description:
      'قائمة العملاء (id, name, phone, class) — للفلترة بالمندوب المسؤول أو ' +
      'بتصنيف العميل.',
    inputSchema: {
      assigned_rep: z.string().optional().describe('فلترة بالمندوب المسؤول'),
      lead_class:   z.string().optional().describe("تصنيف العميل: cold / warm / hot / visited / purchased"),
    },
  },
  async ({ assigned_rep, lead_class }) => {
    try {
      let where = '1=1';
      const params = [];
      if (assigned_rep) { where += ' AND assigned_rep = ?'; params.push(assigned_rep); }
      if (lead_class)   { where += ' AND lead_class = ?';   params.push(lead_class); }
      const leads = db.prepare(`
        SELECT user_id AS id, first_name AS name, phone,
               lead_class AS class, assigned_rep, revisit_status
        FROM lead_profiles
        WHERE ${where}
        ORDER BY last_activity DESC
        LIMIT 300
      `).all(...params);
      return ok({ count: leads.length, leads });
    } catch (e) {
      return fail(e.message);
    }
  }
);

// Tool C — read-only SELECT ────────────────────────────────────────────────────
server.registerTool(
  'run_select_sql',
  {
    description: 'تنفيذ استعلام SELECT للقراءة. يجب أن يبدأ الاستعلام بكلمة SELECT.',
    inputSchema: {
      sql_query: z.string().describe('استعلام SELECT فقط'),
    },
  },
  async ({ sql_query }) => {
    try {
      const r = sqlGuard.runGuardedSelect(db, sql_query, 500);
      if (r.error) return fail(r.error);
      return ok(r);
    } catch (e) {
      return fail(e.message);
    }
  }
);

// Tool D — write SQL: OFF (phase 0) ───────────────────────────────────────────
server.registerTool(
  'execute_write_sql',
  {
    description: 'مقفولة: الكتابة على قاعدة البيانات من MCP متوقفة (المرحلة 0). اعمل التعديل من السيستم نفسه.',
    inputSchema: {
      sql_query: z.string().describe('غير مستخدم — الأداة مقفولة'),
    },
  },
  async () => fail('أداة الكتابة مقفولة (المرحلة 0 — الحماية). مفيش أي تعديل اتعمل.')
);

// ── Start ────────────────────────────────────────────────────────────────────
(async () => {
  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('✅ grand-furniture-crm MCP server running (READ ONLY) — DB:', DB_PATH);
  } catch (e) {
    console.error('[mcp] failed to start:', e.message);
    process.exit(1);
  }
})();
