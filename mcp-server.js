#!/usr/bin/env node
/**
 * mcp-server.js — Model Context Protocol server for the Grand Furniture CRM.
 *
 * A COMPLETELY STANDALONE layer: it does not import or modify server.js or
 * db.js and does not touch any frontend code. It opens its OWN connection to
 * the production database.
 *
 * MODE: READ / WRITE — the AI can read AND modify data (bulk fixes on legacy
 * records). Guardrails: execute_write_sql accepts only DML (INSERT/UPDATE/
 * DELETE/REPLACE) and blocks schema-destroying DDL (DROP/ALTER/TRUNCATE).
 * Every write is logged to stderr as an audit trail.
 *
 * Transport: stdio (for Claude Desktop). NOTE: stdout is reserved for the
 * JSON-RPC protocol — this file only ever logs to stderr.
 */
const path     = require('path');
const Database = require('better-sqlite3');
const { z }    = require('zod');
const { McpServer }            = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

// ── DB connection — standard READ / WRITE ────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'grand_furniture.db');
let db;
try {
  db = new Database(DB_PATH, { fileMustExist: true });
  db.pragma('journal_mode = WAL'); // safe alongside the running app server
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
      'بتصنيف العميل. استخدمها لتحديد السجلات قبل تعديلها بأداة الكتابة.',
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
      const q = String(sql_query || '').trim();
      if (!/^select\b/i.test(q)) {
        return fail('هذه الأداة للقراءة فقط — يجب أن يبدأ الاستعلام بكلمة SELECT.');
      }
      const rows = db.prepare(q).all();
      return ok({ row_count: rows.length, rows: rows.slice(0, 500) });
    } catch (e) {
      return fail(e.message);
    }
  }
);

// Tool D — write SQL (INSERT / UPDATE / DELETE) ───────────────────────────────
server.registerTool(
  'execute_write_sql',
  {
    description:
      'Use this to perform UPDATE, DELETE, or INSERT operations to fix or ' +
      'modify data. WARNING: Always double-check the WHERE clause before ' +
      'executing to avoid mass data corruption.',
    inputSchema: {
      sql_query: z.string().describe('استعلام INSERT أو UPDATE أو DELETE'),
    },
  },
  async ({ sql_query }) => {
    try {
      const q = String(sql_query || '').trim();
      // Must be a data-modification statement.
      if (!/^(insert|update|delete|replace)\b/i.test(q)) {
        return fail('هذه الأداة لعمليات INSERT / UPDATE / DELETE فقط.');
      }
      // Guardrail — block schema-destroying DDL even inside a write tool.
      if (/\b(drop|alter|truncate|attach|detach|vacuum)\b/i.test(q)) {
        return fail('أوامر تعديل الهيكل (DROP/ALTER/TRUNCATE...) غير مسموح بها.');
      }
      const info = db.prepare(q).run();
      console.error(`[mcp][WRITE] rows_affected=${info.changes} :: ${q}`);
      return ok({
        rows_affected: info.changes,
        last_insert_rowid: info.lastInsertRowid,
      });
    } catch (e) {
      return fail(e.message);
    }
  }
);

// ── Start ────────────────────────────────────────────────────────────────────
(async () => {
  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('✅ grand-furniture-crm MCP server running (READ/WRITE) — DB:', DB_PATH);
  } catch (e) {
    console.error('[mcp] failed to start:', e.message);
    process.exit(1);
  }
})();
