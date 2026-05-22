#!/usr/bin/env node
/**
 * mcp-server.js — Model Context Protocol server for the Grand Furniture CRM.
 *
 * A COMPLETELY STANDALONE layer: it does not import server.js or db.js and
 * does not modify any existing code. It opens its OWN connection to the
 * production database in STRICT READ-ONLY mode, so the AI can never write.
 *
 * Transport: stdio (for Claude Desktop). NOTE: stdout is reserved for the
 * JSON-RPC protocol — this file only ever logs to stderr.
 */
const path     = require('path');
const Database = require('better-sqlite3');
const { z }    = require('zod');
const { McpServer }            = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

// ── Read-only DB connection ──────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'grand_furniture.db');
let db;
try {
  db = new Database(DB_PATH, { readonly: true, fileMustExist: true });
} catch (e) {
  console.error(`[mcp] failed to open DB read-only at ${DB_PATH}: ${e.message}`);
  process.exit(1);
}

const currentMonth = () => new Date().toISOString().slice(0, 7); // YYYY-MM
const ok  = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });
const fail = (msg) => ({ content: [{ type: 'text', text: 'خطأ: ' + msg }], isError: true });

// ── MCP server ───────────────────────────────────────────────────────────────
const server = new McpServer({ name: 'grand-furniture-crm', version: '1.0.0' });

// Tool 1 — branch KPIs (revenue / visits / target achievement) ────────────────
server.registerTool(
  'get_branch_kpis',
  {
    description:
      'مؤشرات أداء فرع: إجمالي المبيعات، عدد الزيارات، ونسبة تحقيق المستهدف لشهر معيّن. ' +
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

      // Revenue from purchases.
      let revWhere = `strftime('%Y-%m', created_at) = ?`;
      const revParams = [month];
      if (branch) { revWhere += ' AND branch = ?'; revParams.push(branch); }
      const revenue = db.prepare(
        `SELECT COALESCE(SUM(price), 0) AS r FROM purchases WHERE ${revWhere}`
      ).get(...revParams).r;

      // Visit count from lead_visits.
      let visWhere = `strftime('%Y-%m', visited_at) = ?`;
      const visParams = [month];
      if (branch) { visWhere += ' AND branch = ?'; visParams.push(branch); }
      const visits = db.prepare(
        `SELECT COUNT(DISTINCT user_id) AS n FROM lead_visits WHERE ${visWhere}`
      ).get(...visParams).n;

      // Target from sales_targets.
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

// Tool 2 — lost / cold leads ───────────────────────────────────────────────────
server.registerTool(
  'get_lost_leads',
  {
    description:
      'قائمة العملاء الباردين (cold) أو المغلقين (revisit_status = lost). ' +
      'يمكن الفلترة بمصدر الحملة أو الفئة التي يهتم بها العميل.',
    inputSchema: {
      campaign_source:   z.string().optional().describe('فلترة بمصدر الحملة'),
      category_interest: z.string().optional().describe('فلترة بفئة الاهتمام (last_category)'),
    },
  },
  async ({ campaign_source, category_interest }) => {
    try {
      let where = `(lead_class = 'cold' OR revisit_status = 'lost')`;
      const params = [];
      if (campaign_source)   { where += ' AND campaign_source = ?'; params.push(campaign_source); }
      if (category_interest) { where += ' AND last_category = ?';   params.push(category_interest); }

      const leads = db.prepare(`
        SELECT first_name AS name, phone, lead_class, revisit_status,
               revisit_note AS notes, last_category, campaign_source, last_activity
        FROM lead_profiles
        WHERE ${where}
        ORDER BY last_activity DESC
        LIMIT 200
      `).all(...params);

      return ok({ count: leads.length, leads });
    } catch (e) {
      return fail(e.message);
    }
  }
);

// Tool 3 — flexible read-only SQL ──────────────────────────────────────────────
server.registerTool(
  'run_readonly_sql',
  {
    description:
      'تنفيذ استعلام SELECT للقراءة فقط على قاعدة بيانات الـ CRM. ' +
      'أي أمر تعديل (INSERT/UPDATE/DELETE/DROP/ALTER/REPLACE) ممنوع تماماً.',
    inputSchema: {
      sql_query: z.string().describe('استعلام SELECT فقط — يبدأ بكلمة SELECT'),
    },
  },
  async ({ sql_query }) => {
    try {
      const q = String(sql_query || '').trim();
      // SAFETY 1 — must start with SELECT.
      if (!/^select\b/i.test(q)) {
        return fail('مسموح بأوامر SELECT فقط — يجب أن يبدأ الاستعلام بكلمة SELECT.');
      }
      // SAFETY 2 — block any mutating keyword.
      if (/\b(insert|update|delete|drop|alter|replace|create|attach|detach|pragma)\b/i.test(q)) {
        return fail('الاستعلام يحتوي على أمر غير مسموح به (للقراءة فقط).');
      }
      // SAFETY 3 — the connection itself is read-only, so any write that
      // somehow slipped through is still rejected by SQLite.
      const rows = db.prepare(q).all();
      return ok({ row_count: rows.length, rows: rows.slice(0, 500) });
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
    console.error('✅ grand-furniture-crm MCP server running (read-only) — DB:', DB_PATH);
  } catch (e) {
    console.error('[mcp] failed to start:', e.message);
    process.exit(1);
  }
})();
