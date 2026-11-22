// services/honestNumbers.js — «أرقام حقيقية» (2026-11-22).
//
// The ONE place that says what each analytics step counts. The admin home's
// funnel and cards (GET /api/admin/kpis) and the weekly page «من الإعلان
// للبيعة» (GET /api/admin/ad-funnel) both read it, so the two never disagree.
//
// Rules (every one is checked by backend/scripts/smoke-honest-numbers.js):
//   • Days are CAIRO days (Intl, Africa/Cairo, summer time aware): an event at
//     23:30 Cairo on the 20th is on the 20th, never the UTC day.
//   • People, not events: every step is a count of DISTINCT customers.
//   • The chat steps never hold a walk-in. A walk-in event is one the
//     reception's walk-in route wrote: events.source = 'walkin' (since this
//     build), or — the older rows, never rewritten — a branch_selected with
//     raw_payload IS NULL (the chat intake always stores the request's body;
//     the walk-in route was the only writer that left it empty).
//   • A «chat person» has at least one chat event (any time). A walk-in
//     customer who never chatted is the «زيارة مباشرة» row, never a campaign.
//   • A phone counts as «ساب رقم» only when it came from the chat:
//     lead_phones.source = 'chat' (written by the chat intake since r2); the
//     reception's ('walkin') and a number staff typed ('staff') never count.
//     Older rows (source NULL) count unless written within 5 minutes of the
//     same customer's walk-in check-in (that one is the reception's).
//   • A chat person's campaign_source «زيارة مباشرة» is not an ad: the old
//     walk-in route wrote it on chat leads who had no source. It is «من غير
//     إعلان» ('none') — «زيارة مباشرة» is only ever the people who never chatted.
//   • Steps: chats (any chat event) → phone (his FIRST chat phone) → branch /
//     coming (a chat branch_selected or visit_planned) → visited (a check-in,
//     or for visits before check-ins existed the first visit lead_visits kept)
//     → bought (a contract). Value = the paid amount when typed, else the
//     admin-only list estimate (purchase_estimates) — «تقريبي».
//   • Two views of one table:
//       period — what happened in the range: each step by its OWN date. The
//                steps are different people, so they are counts only (no %).
//       cohort — the people whose FIRST chat fell in the range, and how far
//                they got by today (every later step counted whenever it came).
//                NESTED (r2): a person counts at every step up to the furthest
//                one he reached — «وصلوا لحد الخطوة دي أو أبعد». Someone who
//                visited without choosing a branch in the chat (or bought with
//                no phone from the chat) counts at the steps before too, so a
//                step is never bigger than the one before it and its share of
//                the one before is the same people. With a branch filter the
//                furthest step is taken at that branch for steps 3–5 (steps
//                1–2 stay «كل الفروع», all branches). In the per-branch table
//                each person is in ONE row: the branch he bought at (first
//                contract), else visited (first visit), else first chose in
//                the chat, else «لسه مختارش فرع». Contracts and value stay by
//                the contract's own branch (a branch's sales are its own).
//   • Branch: a step that carries a branch (branch / coming, visit, contract)
//     is filtered by its own branch. Chats and phones carry none: with a
//     branch filter they stay «كل الفروع» (the answer says so), and in the
//     per-branch table of the period view a chat / phone belongs to the
//     branch the customer first chose in the chat (up to the range's end) —
//     else «لسه مختارش فرع» (the cohort view: one row per person, above).
'use strict';

module.exports = function makeHonestNumbers({ cairoDay, cairoDayBoundsSql, sqlUtcToDate, normalizeBranch }) {
  const WALKIN_EVENT = (a = 'e') =>
    `(COALESCE(${a}.source, '') = 'walkin' OR (${a}.event_type = 'branch_selected' AND ${a}.raw_payload IS NULL))`;
  const CHAT_EVENT = (a = 'e') => `NOT ${WALKIN_EVENT(a)}`;
  const WALKIN_PHONE_MINUTES = 5;

  const isDay = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)
    && !Number.isNaN(Date.parse(v + 'T00:00:00Z')) && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;
  const dayOf = (s) => { const d = sqlUtcToDate(s); return d && !Number.isNaN(d.getTime()) ? cairoDay(d) : null; };
  const msOf = (s) => { const d = sqlUtcToDate(s); return d ? d.getTime() : NaN; };
  const inRange = (day, from, to) => !!day && (!from || day >= from) && (!to || day <= to);
  const nb = (b) => (b == null || String(b).trim() === '' ? null : (normalizeBranch(b) || String(b).trim()));
  // ` AND datetime(col) >= ? AND datetime(col) < ?` — the UTC bounds of [from, to] Cairo days.
  function rangeSql(col, from, to) {
    const parts = []; const params = [];
    if (from) { parts.push(`datetime(${col}) >= ?`); params.push(cairoDayBoundsSql(from)[0]); }
    if (to)   { parts.push(`datetime(${col}) < ?`);  params.push(cairoDayBoundsSql(to)[1]); }
    return { clause: parts.length ? ' AND ' + parts.join(' AND ') : '', params };
  }
  const addDays = (day, n) => { const [y, m, d] = day.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10); };
  // Weeks run Saturday → Friday (the showrooms' week; Friday is the weekend day).
  function weekOf(day) {
    const [y, m, d] = day.split('-').map(Number);
    const dow = new Date(Date.UTC(y, m - 1, d)).getUTCDay();   // 0 Sun … 6 Sat
    const back = (dow + 1) % 7;                                // days since Saturday
    const from = addDays(day, -back);
    return { from, to: addDays(from, 6) };
  }

  // ── the raw facts, loaded once per answer ───────────────────────────────
  // Everything is read with plain SELECTs (no write, no network). The volumes
  // are a showroom's: thousands of people, not millions.
  function loadFacts(db) {
    const chatFirst = new Map();     // user → first chat event (UTC text)
    for (const r of db.prepare(`SELECT e.user_id, MIN(e.created_at) AS at FROM events e WHERE ${CHAT_EVENT('e')} GROUP BY e.user_id`).all()) {
      chatFirst.set(r.user_id, r.at);
    }
    const source = new Map();
    for (const r of db.prepare(`SELECT user_id, campaign_source FROM lead_profiles`).all()) source.set(r.user_id, r.campaign_source);

    // walk-in desk moments (to tell the reception's phone rows from the chat's)
    const walkinAt = new Map();
    for (const r of db.prepare(`SELECT user_id, checked_in_at FROM visit_checkins WHERE source = 'walkin'`).all()) {
      const t = msOf(r.checked_in_at);
      if (!walkinAt.has(r.user_id)) walkinAt.set(r.user_id, []);
      walkinAt.get(r.user_id).push(t);
    }
    const fromDesk = (uid, at) => {
      const ts = walkinAt.get(uid); if (!ts) return false;
      const t = msOf(at);
      return ts.some((w) => Math.abs(w - t) <= WALKIN_PHONE_MINUTES * 60e3);
    };
    const firstChatPhone = new Map();   // user → UTC text of his first chat phone
    for (const r of db.prepare(`SELECT user_id, created_at, source FROM lead_phones ORDER BY datetime(created_at), id`).all()) {
      if (!chatFirst.has(r.user_id) || firstChatPhone.has(r.user_id)) continue;
      if (r.source != null ? r.source !== 'chat' : fromDesk(r.user_id, r.created_at)) continue;
      firstChatPhone.set(r.user_id, r.created_at);
    }

    // chat «branch / coming» steps (branch_selected | visit_planned), oldest first
    const branchSteps = db.prepare(`
      SELECT e.user_id, e.event_type, e.created_at,
             CASE WHEN e.event_type = 'branch_selected' THEN COALESCE(NULLIF(e.branch, ''), e.event_value)
                  ELSE NULLIF(e.branch, '') END AS branch
      FROM events e
      WHERE e.event_type IN ('branch_selected', 'visit_planned') AND ${CHAT_EVENT('e')}
      ORDER BY datetime(e.created_at), e.id
    `).all().map((r) => ({ user_id: r.user_id, type: r.event_type, at: r.created_at, day: dayOf(r.created_at), branch: nb(r.branch) }));

    // visits: one per (person, branch, Cairo day) — check-ins, plus the first
    // visits lead_visits kept from before check-ins existed.
    const visitKey = new Set(); const visits = [];
    for (const r of db.prepare(`SELECT user_id, branch, visit_day, source FROM visit_checkins`).all()) {
      const k = `${r.user_id}|${nb(r.branch)}|${r.visit_day}`;
      if (visitKey.has(k)) continue;
      visitKey.add(k); visits.push({ user_id: r.user_id, branch: nb(r.branch), day: r.visit_day, source: r.source });
    }
    for (const r of db.prepare(`SELECT user_id, branch, visited_at FROM lead_visits`).all()) {
      const day = dayOf(r.visited_at);
      const k = `${r.user_id}|${nb(r.branch)}|${day}`;
      if (!day || visitKey.has(k)) continue;
      visitKey.add(k); visits.push({ user_id: r.user_id, branch: nb(r.branch), day, source: 'first_visit' });
    }

    const purchases = db.prepare(`
      SELECT p.id, p.user_id, p.branch, p.rep, p.price, p.created_at, e.list_total_estimate AS estimate
      FROM purchases p LEFT JOIN purchase_estimates e ON e.purchase_id = p.id
      ORDER BY datetime(p.created_at), p.id
    `).all().map((r) => {
      const paid = Number(r.price) > 0 ? Number(r.price) : null;
      const est  = r.estimate != null ? Number(r.estimate) : null;
      return { id: r.id, user_id: r.user_id, branch: nb(r.branch), day: dayOf(r.created_at), rep: r.rep ?? null,
        paid: paid || 0,
        value: paid != null ? paid : (est != null ? est : 0), approx: paid == null && est != null, no_value: paid == null && est == null };
    });
    visits.sort((a, b) => (a.day < b.day ? -1 : a.day > b.day ? 1 : 0));
    return { chatFirst, source, firstChatPhone, branchSteps, visits, purchases };
  }

  // The branch a chat customer first chose in the chat, up to `to` (null = ever).
  function firstBranchMap(facts, to) {
    const m = new Map();
    for (const s of facts.branchSteps) {
      if (s.type !== 'branch_selected' || !s.branch || m.has(s.user_id)) continue;
      if (to && s.day > to) continue;
      m.set(s.user_id, s.branch);
    }
    return m;
  }

  // The walk-in label the old reception route wrote as a campaign_source (on a
  // new walk-in, and on a known chat lead who had none, before C1.10).
  const WALKIN_SOURCE_LABEL = 'زيارة مباشرة';
  const sourceKey = (facts, uid) => {
    if (!facts.chatFirst.has(uid)) return 'walkin';
    const s = facts.source.get(uid);
    const v = s == null ? '' : String(s).trim();
    return v === '' || v === WALKIN_SOURCE_LABEL ? 'none' : v;
  };

  // ── one table: people per group per step ────────────────────────────────
  function build(db, { from, to, mode = 'period', branch = null, groupBy }) {
    const facts = loadFacts(db);
    const groups = new Map();
    const g = (k) => {
      if (!groups.has(k)) groups.set(k, { key: k, chats: new Set(), phones: new Set(), branch: new Set(), visited: new Set(),
        bought: new Set(), contracts: 0, value: 0, approx: 0, no_value: 0,
        walkin_visited: new Set(), walkin_bought: new Set(), walkin_contracts: 0, walkin_value: 0, walkin_approx: 0 });
      return groups.get(k);
    };
    const isChat = (uid) => facts.chatFirst.has(uid);
    const branchOk = (b) => !branch || b === branch;
    const cohort = mode === 'cohort'
      ? new Set([...facts.chatFirst].filter(([, at]) => inRange(dayOf(at), from, to)).map(([u]) => u))
      : null;

    if (cohort) {
      // NESTED: each cohort person lands in one row and counts at every step up
      // to the furthest one he reached (steps 3–5 at the filter's branch).
      const per = new Map([...cohort].map((u) => [u, { chose: [], visits: [], buys: [] }]));
      for (const s of facts.branchSteps) per.get(s.user_id)?.chose.push(s);       // oldest first
      for (const v of facts.visits)      per.get(v.user_id)?.visits.push(v);      // by day
      for (const p of facts.purchases)   per.get(p.user_id)?.buys.push(p);        // oldest first
      for (const [uid, f] of per) {
        const any = f.buys.length ? 5 : f.visits.length ? 4 : f.chose.length ? 3 : facts.firstChatPhone.has(uid) ? 2 : 1;
        const at = f.buys.some((p) => branchOk(p.branch)) ? 5
          : f.visits.some((v) => branchOk(v.branch)) ? 4
          : f.chose.some((c) => branchOk(c.branch)) ? 3 : 0;
        let key;
        if (groupBy === 'branch') {
          const firstBranch = (xs) => (xs.find((x) => x.branch) || {}).branch;
          key = firstBranch(f.buys) || firstBranch(f.visits) || firstBranch(f.chose) || 'no_branch';
        } else key = groupBy === 'source' ? sourceKey(facts, uid) : 'all';
        const row = g(key);
        row.chats.add(uid);
        if (any >= 2) row.phones.add(uid);
        if (at >= 3) row.branch.add(uid);
        if (at >= 4) row.visited.add(uid);
        if (at >= 5) row.bought.add(uid);
      }
    } else {
      // period: each step by its own day — counts only, not the same people.
      const firstBranch = firstBranchMap(facts, to);
      const groupOf = groupBy === 'branch'
        ? (uid, stepBranch) => (stepBranch != null ? stepBranch : (firstBranch.get(uid) || 'no_branch'))
        : groupBy === 'source' ? (uid) => sourceKey(facts, uid) : () => 'all';
      const r = rangeSql('e.created_at', from, to);
      for (const row of db.prepare(`SELECT DISTINCT e.user_id FROM events e WHERE ${CHAT_EVENT('e')}${r.clause}`).all(...r.params)) {
        g(groupOf(row.user_id, null)).chats.add(row.user_id);
      }
      for (const [uid, at] of facts.firstChatPhone) {
        if (inRange(dayOf(at), from, to)) g(groupOf(uid, null)).phones.add(uid);
      }
      for (const s of facts.branchSteps) {
        if (!inRange(s.day, from, to) || !branchOk(s.branch)) continue;
        if (groupBy === 'branch' && !s.branch) continue;   // a step with no branch has no row in the branch table
        g(groupOf(s.user_id, groupBy === 'branch' ? s.branch : null)).branch.add(s.user_id);
      }
      for (const v of facts.visits) {
        if (!isChat(v.user_id) || !branchOk(v.branch) || !inRange(v.day, from, to)) continue;
        g(groupOf(v.user_id, groupBy === 'branch' ? (v.branch || 'no_branch') : null)).visited.add(v.user_id);
      }
    }

    // walk-ins who never chatted: by their own day in both views — the
    // «زيارة مباشرة» row, or the branch's walk-in line; never a chat step
    for (const v of facts.visits) {
      if (isChat(v.user_id) || !branchOk(v.branch) || !inRange(v.day, from, to)) continue;
      if (groupBy === 'branch') g(v.branch || 'no_branch').walkin_visited.add(v.user_id);
      else g(groupBy === 'source' ? 'walkin' : 'all').visited.add(v.user_id);
    }
    // contracts (value): a chat person's by his own day (period) or whenever
    // (cohort); a walk-in's by its own day. In the branch table by the
    // contract's own branch.
    for (const p of facts.purchases) {
      if (!branchOk(p.branch)) continue;
      const chat = isChat(p.user_id);
      if (chat ? !(cohort ? cohort.has(p.user_id) : inRange(p.day, from, to)) : !inRange(p.day, from, to)) continue;
      const k = groupBy === 'branch' ? (p.branch || 'no_branch')
        : groupBy === 'source' ? sourceKey(facts, p.user_id) : 'all';
      const row = g(k);
      if (groupBy === 'branch' && !chat) {
        row.walkin_bought.add(p.user_id); row.walkin_contracts += 1; row.walkin_value += p.value;
        if (p.approx) row.walkin_approx += 1;
        continue;
      }
      if (!cohort || !chat) row.bought.add(p.user_id);   // cohort: «اشتروا» is the nested step above
      row.contracts += 1; row.value += p.value; if (p.approx) row.approx += 1; if (p.no_value) row.no_value += 1;
    }

    const out = [...groups.values()].map((r) => ({
      key: r.key,
      chats: r.key === 'walkin' ? null : r.chats.size,
      phones: r.key === 'walkin' ? null : r.phones.size,
      branch_or_coming: r.key === 'walkin' ? null : r.branch.size,
      visited: r.visited.size,
      bought: r.bought.size,
      contracts: r.contracts,
      value: r.value,
      value_approx: r.approx > 0,
      approx_contracts: r.approx,
      no_value_contracts: r.no_value,
      ...(groupBy === 'branch' ? { walkin_visited: r.walkin_visited.size, walkin_bought: r.walkin_bought.size,
        walkin_contracts: r.walkin_contracts, walkin_value: r.walkin_value, walkin_value_approx: r.walkin_approx > 0 } : {}),
    }));
    return { rows: out, facts };
  }

  // Sum of the chat rows (walk-in row left out) — the «كل الشات» line.
  function chatTotals(rows) {
    const t = { chats: 0, phones: 0, branch_or_coming: 0, visited: 0, bought: 0, contracts: 0, value: 0, approx_contracts: 0, no_value_contracts: 0 };
    for (const r of rows) {
      if (r.key === 'walkin') continue;
      for (const k of Object.keys(t)) t[k] += r[k] || 0;
    }
    t.value_approx = t.approx_contracts > 0;
    return t;
  }

  // GET /api/admin/kpis's funnel: the cohort of the range (people whose first
  // chat fell in it; no range = everyone who ever chatted), the steps 3–5 by
  // the branch filter, plus the range's walk-ins on their own line.
  function homeFunnel(db, { from, to, branch }) {
    const { rows } = build(db, { from, to, mode: 'cohort', branch, groupBy: 'source' });
    const t = chatTotals(rows);
    const w = rows.find((r) => r.key === 'walkin') || { visited: 0, bought: 0 };
    return {
      mode: 'cohort', from: from || null, to: to || null, branch: branch || null,
      stages: [
        { key: 'chats',            count: t.chats,            branch_scoped: false },
        { key: 'phones',           count: t.phones,           branch_scoped: false },
        { key: 'branch_or_coming', count: t.branch_or_coming, branch_scoped: true },
        { key: 'visited',          count: t.visited,          branch_scoped: true },
        { key: 'bought',           count: t.bought,           branch_scoped: true },
      ],
      walkin: { visited: w.visited, bought: w.bought },
    };
  }

  // Visitors / buyers of a period (everyone, walk-ins included) — the home
  // cards «إجمالي الزيارات» and «نسبة الإغلاق» (buyers AMONG those visitors).
  function periodVisits(db, { from, to, branch }) {
    const facts = loadFacts(db);
    const ok = (b) => !branch || b === branch;
    const visitors = new Set(); let checkins = 0; const byBranch = new Map();
    for (const v of facts.visits) {
      if (!ok(v.branch) || !inRange(v.day, from, to)) continue;
      visitors.add(v.user_id); checkins += 1;
      const k = v.branch || 'no_branch';
      if (!byBranch.has(k)) byBranch.set(k, new Set());
      byBranch.get(k).add(v.user_id);
    }
    const buyers = new Set();
    for (const p of facts.purchases) if (ok(p.branch) && inRange(p.day, from, to)) buyers.add(p.user_id);
    let boughtOfVisitors = 0;
    for (const u of visitors) if (buyers.has(u)) boughtOfVisitors += 1;
    return {
      visitors: visitors.size, checkins, bought_of_visitors: boughtOfVisitors,
      by_branch: [...byBranch].map(([b, s]) => ({ branch: b, visits: s.size })).sort((a, b) => b.visits - a.visits),
    };
  }

  // Every contract written in the range, by its own Cairo day — chat or walk-in,
  // whichever view the page is on: «قيمة البيع في الأسبوع» is always this.
  function rangeSales(facts, from, to) {
    const t = { contracts: 0, value: 0, approx_contracts: 0, no_value_contracts: 0 };
    for (const p of facts.purchases) {
      if (!inRange(p.day, from, to)) continue;
      t.contracts += 1; t.value += p.value; if (p.approx) t.approx_contracts += 1; if (p.no_value) t.no_value_contracts += 1;
    }
    t.value_approx = t.approx_contracts > 0;
    return t;
  }

  // GET /api/admin/ad-funnel — the weekly «من الإعلان للبيعة» table.
  function weekly(db, { from, to, mode }) {
    const built = build(db, { from, to, mode, groupBy: 'source' });
    const bySource = built.rows;
    const byBranch = build(db, { from, to, mode, groupBy: 'branch' }).rows;
    const order = (k) => (k === 'walkin' ? 3 : k === 'none' ? 2 : k === 'no_branch' ? 2 : 0);
    const sortRows = (rs) => rs.sort((a, b) => order(a.key) - order(b.key) || (b.chats || 0) - (a.chats || 0) || b.visited - a.visited);
    const w = bySource.find((r) => r.key === 'walkin');
    return {
      // cohort: nested («وصلوا لحد الخطوة دي أو أبعد»); period: each step by its own day
      steps_rule: mode === 'cohort' ? 'reached_or_further' : 'own_day',
      by_source: sortRows(bySource),
      by_branch: sortRows(byBranch).map((r) => ({ ...r, branch: r.key })),
      chat_totals: chatTotals(bySource),
      walkin_totals: w ? { visited: w.visited, bought: w.bought, contracts: w.contracts, value: w.value, value_approx: w.value_approx }
        : { visited: 0, bought: 0, contracts: 0, value: 0, value_approx: false },
      week_sales: rangeSales(built.facts, from, to),
    };
  }

  // GET /api/sales/analytics («أداء السيلز») — per salesperson and per branch,
  // every number from the range (Cairo days):
  //   served      — distinct people with a visit in the range at the branch (a
  //                 check-in; before check-ins existed, the first visit
  //                 lead_visits kept), credited to the salesperson lead_visits
  //                 names for that (person, branch). A returning customer
  //                 counts in the week he came back.
  //   bought      — of those people, the ones who bought from him at that
  //                 branch in the range (per branch: from anyone there).
  //   contracts / total_sales — his contracts at the branch in the range (the
  //                 paid amount, once per contract), whether or not that
  //                 customer's visit is in the range.
  // A row is any (salesperson, branch) with people served OR contracts.
  function salesByRep(db, { from, to, sales = null, branch = null }) {
    const facts = loadFacts(db);
    const wantBranch = branch ? nb(branch) : null;
    const ok = (b) => !wantBranch || b === wantBranch;
    const repOf = new Map();
    for (const r of db.prepare(`SELECT user_id, branch, sales_rep FROM lead_visits WHERE sales_rep IS NOT NULL AND TRIM(sales_rep) <> ''`).all()) {
      repOf.set(`${r.user_id}|${nb(r.branch)}`, r.sales_rep);
    }
    const rows = new Map(); const branches = new Map();
    const row = (rep, b) => {
      const k = `${rep}|${b}`;
      if (!rows.has(k)) rows.set(k, { sales_rep: rep, branch: b, served: new Set(), buyers: new Set(), contracts: 0, total_sales: 0 });
      return rows.get(k);
    };
    const brow = (b) => {
      if (!branches.has(b)) branches.set(b, { branch: b, served: new Set(), buyers: new Set() });
      return branches.get(b);
    };
    for (const v of facts.visits) {
      if (!ok(v.branch) || !inRange(v.day, from, to)) continue;
      const rep = repOf.get(`${v.user_id}|${v.branch}`);
      if (!rep || (sales && rep !== sales)) continue;
      row(rep, v.branch).served.add(v.user_id);
      brow(v.branch).served.add(v.user_id);
    }
    for (const p of facts.purchases) {
      if (!ok(p.branch) || !inRange(p.day, from, to)) continue;
      brow(p.branch).buyers.add(p.user_id);                      // anyone's buyer at the branch
      if (p.rep == null || String(p.rep).trim() === '' || (sales && p.rep !== sales)) continue;
      const r = row(p.rep, p.branch);
      r.contracts += 1; r.total_sales += p.paid; r.buyers.add(p.user_id);
    }
    const bySales = [...rows.values()].map((r) => {
      const served = r.served.size;
      let bought = 0; for (const u of r.served) if (r.buyers.has(u)) bought += 1;
      return { sales_rep: r.sales_rep, branch: r.branch, served, bought, total_sales: r.total_sales, contracts: r.contracts };
    }).sort((a, b) => b.total_sales - a.total_sales || b.served - a.served);
    const byBranch = [...branches.values()].map((b) => {
      let bought = 0; for (const u of b.served) if (b.buyers.has(u)) bought += 1;
      return { branch: b.branch, served: b.served.size, bought };
    }).filter((b) => b.served > 0).sort((a, b) => b.bought - a.bought || b.served - a.served);
    return { bySales, byBranch };
  }

  return { WALKIN_EVENT, CHAT_EVENT, isDay, rangeSql, weekOf, addDays, dayOf, homeFunnel, periodVisits, weekly, build, chatTotals,
    salesByRep, normBranch: nb };
};
