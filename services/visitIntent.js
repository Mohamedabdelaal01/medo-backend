'use strict';
// ════════════════════════════════════════════════════════════════════════════
// O6 / O4 — what a customer looked at, and the day he said he'd come.
//
//   viewedFor(db, userIds)         → Map user_id → viewed
//       viewed = { items: [name…],  the last 5 DISTINCT product_details /
//                                   category_request names, newest first
//                                   (product, else category)
//                  visit_planned: { value, planned_day, when, said_at } | null
//                                   (the LATEST visit_planned)
//                  campaign_source }
//   latestPlans(db, userIds)       → Map user_id → plan (the latest visit_planned)
//       plan = { value, planned_day, when, branch, said_at, came }
//         when   — 'today' | 'tomorrow' (planned_day vs the CAIRO day now),
//                  'past' (planned_day before today), or null (no date:
//                  this_week / unsure / other)
//         branch — the event's branch, else the profile's preferred_branch
//         came   — he checked in (any branch) at/after the plan was said, or,
//                  for a plan for today, at all today
//   expectedVisits(db, branch)     → «جايين النهارده» rows for one branch
//   plannedBadge(plan, branch)     → 'today' | 'tomorrow' | null
//
// Read-only: no writes, no CAPI, no ManyChat. Day boundaries are Cairo days
// (Intl, Africa/Cairo); planned_day is the Cairo date the intake stored (C1.8).
// ════════════════════════════════════════════════════════════════════════════

const CAIRO_TZ = 'Africa/Cairo';
const _dayFmt = new Intl.DateTimeFormat('en-CA', { timeZone: CAIRO_TZ, year: 'numeric', month: '2-digit', day: '2-digit' });

// 'YYYY-MM-DD' of `d` in Cairo.
function cairoDayOf(d = new Date()) {
  const o = {};
  for (const p of _dayFmt.formatToParts(d)) o[p.type] = p.value;
  return `${o.year}-${o.month}-${o.day}`;
}
// The calendar day after `day` (date arithmetic, DST-safe).
function nextDay(day) {
  const [y, m, d] = day.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d + 1)).toISOString().slice(0, 10);
}

const VIEWED_MAX   = 5;
const VIEWED_SCAN  = 200;     // newest events read per customer to find 5 distinct names
const CHUNK        = 500;     // ids per IN (…) query

// A stored UTC 'YYYY-MM-DD HH:MM:SS' (or ISO) → 'YYYY-MM-DDTHH:MM:SSZ', or null.
function isoZ(s) {
  if (!s) return null;
  const v = String(s);
  const d = new Date(/Z$|[+-]\d\d:\d\d$/.test(v) ? v : v.replace(' ', 'T') + 'Z');
  return isNaN(d) ? null : d.toISOString().slice(0, 19) + 'Z';
}

function whenOf(plannedDay, today, tomorrow) {
  if (!plannedDay) return null;
  if (plannedDay === today) return 'today';
  if (plannedDay === tomorrow) return 'tomorrow';
  return plannedDay < today ? 'past' : null;   // a later date never comes from the intake
}

const nameKey = (s) => String(s).replace(/\s+/g, ' ').trim().toLowerCase();
const clean   = (s) => (s == null ? '' : String(s).replace(/\s+/g, ' ').trim());

function chunked(ids, fn) {
  const list = [...new Set((ids || []).filter(Boolean).map(String))];
  for (let i = 0; i < list.length; i += CHUNK) fn(list.slice(i, i + CHUNK));
}

// The latest visit_planned of each customer, with «did he come since».
function latestPlans(db, userIds, now = new Date()) {
  const today = cairoDayOf(now), tomorrow = nextDay(today);
  const out = new Map();
  chunked(userIds, (ids) => {
    const marks = ids.map(() => '?').join(', ');
    const rows = db.prepare(`
      SELECT x.user_id, x.event_value, x.planned_day, x.created_at,
             COALESCE(x.branch, lp.preferred_branch) AS plan_branch,
             CASE WHEN EXISTS (
                    SELECT 1 FROM visit_checkins c
                    WHERE c.user_id = x.user_id
                      AND (datetime(c.checked_in_at) >= datetime(x.created_at)
                           OR (x.planned_day = ? AND c.visit_day = ?))
                  ) OR EXISTS (
                    SELECT 1 FROM lead_visits v
                    WHERE v.user_id = x.user_id AND datetime(v.visited_at) >= datetime(x.created_at)
                  ) THEN 1 ELSE 0 END AS came
      FROM (
        SELECT e.user_id, e.event_value, e.planned_day, e.branch, e.created_at,
               ROW_NUMBER() OVER (PARTITION BY e.user_id
                                  ORDER BY datetime(e.created_at) DESC, e.id DESC) AS rn
        FROM events e
        WHERE e.event_type = 'visit_planned' AND e.user_id IN (${marks})
      ) x
      LEFT JOIN lead_profiles lp ON lp.user_id = x.user_id
      WHERE x.rn = 1
    `).all(today, today, ...ids);
    for (const r of rows) {
      out.set(r.user_id, {
        value:       r.event_value || null,
        planned_day: r.planned_day || null,
        when:        whenOf(r.planned_day, today, tomorrow),
        branch:      r.plan_branch || null,
        said_at:     isoZ(r.created_at),
        came:        r.came === 1,
      });
    }
  });
  return out;
}

// «جاي النهارده» / «جاي بكره» for a list of `branch`: the plan is for today or
// tomorrow, he hasn't come since, and its branch is this one (or unknown).
function plannedBadge(plan, branch) {
  if (!plan || plan.came) return null;
  if (plan.when !== 'today' && plan.when !== 'tomorrow') return null;
  if (branch && plan.branch && plan.branch !== branch) return null;
  return plan.when;
}

// What each customer looked at + his latest stated day + his ad.
function viewedFor(db, userIds, now = new Date()) {
  const out = new Map();
  const plans = latestPlans(db, userIds, now);
  const evStmt = db.prepare(`
    SELECT event_type, event_value, product_id, category
    FROM events
    WHERE user_id = ? AND event_type IN ('product_details', 'category_request')
    ORDER BY datetime(created_at) DESC, id DESC
    LIMIT ${VIEWED_SCAN}
  `);
  const srcStmt = db.prepare(`SELECT campaign_source FROM lead_profiles WHERE user_id = ?`);
  chunked(userIds, (ids) => {
    for (const uid of ids) {
      const items = [], seen = new Set();
      for (const e of evStmt.all(uid)) {
        const name = e.event_type === 'product_details'
          ? (clean(e.product_id) || clean(e.event_value) || clean(e.category))
          : (clean(e.category) || clean(e.event_value));
        if (!name) continue;
        const k = nameKey(name);
        if (seen.has(k)) continue;
        seen.add(k); items.push(name);
        if (items.length >= VIEWED_MAX) break;
      }
      const p = plans.get(uid);
      out.set(uid, {
        items,
        visit_planned: p ? { value: p.value, planned_day: p.planned_day, when: p.when, said_at: p.said_at } : null,
        campaign_source: srcStmt.get(uid)?.campaign_source || null,
      });
    }
  });
  return out;
}

// «جايين النهارده»: customers whose LATEST visit_planned is for today or
// tomorrow (Cairo) at `branch` (the event's branch, else preferred_branch) and
// who haven't come since. Today first, then tomorrow; newest plan first.
function expectedVisits(db, branch, now = new Date()) {
  const today = cairoDayOf(now), tomorrow = nextDay(today);
  // candidates: anyone with a visit_planned for one of the two days (latest checked below)
  const cand = db.prepare(`
    SELECT DISTINCT user_id FROM events
    WHERE event_type = 'visit_planned' AND planned_day IN (?, ?)
  `).all(today, tomorrow).map(r => r.user_id);
  if (!cand.length) return { day: today, tomorrow, rows: [] };
  const plans = latestPlans(db, cand, now);
  const keep = cand.filter(uid => {
    const p = plans.get(uid);
    return p && !p.came && (p.when === 'today' || p.when === 'tomorrow') && p.branch === branch;
  });
  const rows = [];
  chunked(keep, (ids) => {
    const marks = ids.map(() => '?').join(', ');
    rows.push(...db.prepare(`
      SELECT lp.user_id, lp.first_name, lp.last_name, lp.lead_class, lp.campaign_source,
             lp.phone AS profile_phone,
             (SELECT GROUP_CONCAT(ph.phone, ' ، ') FROM lead_phones ph WHERE ph.user_id = lp.user_id) AS phones
      FROM lead_profiles lp WHERE lp.user_id IN (${marks})
    `).all(...ids));
  });
  const viewed = viewedFor(db, rows.map(r => r.user_id), now);
  const list = rows.map(r => {
    const p = plans.get(r.user_id);
    return {
      user_id:         r.user_id,
      first_name:      r.first_name || null,
      last_name:       r.last_name || null,
      phones:          r.phones || r.profile_phone || null,
      lead_class:      r.lead_class || null,
      campaign_source: r.campaign_source || null,
      planned_when:    p.when,
      planned_day:     p.planned_day,
      said_at:         p.said_at,
      viewed:          viewed.get(r.user_id) || { items: [], visit_planned: null, campaign_source: null },
    };
  }).sort((a, b) => (a.planned_when === b.planned_when ? 0 : a.planned_when === 'today' ? -1 : 1)
                 || String(b.said_at || '').localeCompare(String(a.said_at || '')));
  return { day: today, tomorrow, rows: list };
}

// The SLA hours for a lead who said he comes today/tomorrow (O4). A setting:
// sla_hours_planned (default 4, 1–48). `raw` is the stored string.
const SLA_PLANNED_DEFAULT = 4;
function slaHoursPlanned(raw) {
  const n = Number(String(raw ?? '').trim());
  if (!Number.isFinite(n) || n <= 0) return SLA_PLANNED_DEFAULT;
  return Math.min(48, Math.max(1, n));
}

module.exports = {
  cairoDayOf, nextDay, latestPlans, plannedBadge, viewedFor, expectedVisits,
  slaHoursPlanned, SLA_PLANNED_DEFAULT, VIEWED_MAX,
};
