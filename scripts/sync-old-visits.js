#!/usr/bin/env node
/**
 * sync-old-visits.js — ONE-TIME backfill of historical in-store visitors to Meta
 * CAPI as `FindLocation` events (action_source: physical_store), to instantly seed
 * the "Store Visitors" Custom Audience.
 *
 * Run on the Railway server (where META_* env vars are injected):
 *     railway ssh "node /app/scripts/sync-old-visits.js"
 *
 * - Source of truth = physical visits: a `lead_visits` row OR visit_confirmed=1.
 * - Idempotent: a STABLE per-customer event_id (`visit_hist_<user_id>`) means
 *   re-running the script does NOT double-count — Meta deduplicates by event_id.
 * - Rate-limit safe: fires one event, then waits DELAY_MS before the next.
 * - Never touches the CRM flow; read-only on the DB. Reuses the live triggers'
 *   exact payload + the `{ actionSource: 'physical_store' }` override (which makes
 *   metaCapi omit event_source_url, since that's a website-only field).
 */
const { getLiveDb }     = require('../db');
const { sendMetaEvent } = require('../services/metaCapi');

const sleep    = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const DELAY_MS = 80;   // pace between Meta calls — comfortably under the rate limit

async function main() {
  if (!process.env.META_PIXEL_ID || !process.env.META_ACCESS_TOKEN) {
    console.error('✗ META_PIXEL_ID / META_ACCESS_TOKEN not set — aborting. Nothing was sent.');
    process.exit(1);
  }

  const db = getLiveDb();

  // Historical in-store visitors: visited the showroom (a lead_visits row, or
  // visit_confirmed=1) AND have a phone we can hash. branch = most-recent visit
  // branch (fallback preferred_branch). Stray demo rows excluded defensively.
  const phoneSub = `(SELECT ph.phone FROM lead_phones ph WHERE ph.user_id = lp.user_id ORDER BY ph.id LIMIT 1)`;
  const visitors = db.prepare(`
    SELECT lp.user_id,
           lp.first_name,
           lp.last_name,
           lp.gender,
           COALESCE(lp.phone, ${phoneSub}) AS phone,
           COALESCE(
             (SELECT v.branch FROM lead_visits v WHERE v.user_id = lp.user_id ORDER BY v.visited_at DESC LIMIT 1),
             lp.preferred_branch
           ) AS branch
    FROM lead_profiles lp
    WHERE (lp.visit_confirmed = 1 OR EXISTS (SELECT 1 FROM lead_visits v WHERE v.user_id = lp.user_id))
      AND lp.user_id NOT LIKE 'dmol_%'
      AND COALESCE(lp.phone, ${phoneSub}) IS NOT NULL
  `).all();

  console.log(`Found ${visitors.length} past in-store visits with a phone. Starting sync…`);
  if (visitors.length === 0) { console.log('Nothing to sync. Done.'); return; }

  let dispatched = 0;
  for (const v of visitors) {
    sendMetaEvent(
      'FindLocation',
      { phone: v.phone, firstName: v.first_name, lastName: v.last_name,
        gender: v.gender, branch: v.branch, externalId: v.user_id },
      `visit_hist_${v.user_id}`,            // stable → idempotent re-runs
      undefined,
      { actionSource: 'physical_store' },   // omits event_source_url automatically
    );
    dispatched++;
    if (dispatched % 100 === 0 || dispatched === visitors.length) {
      console.log(`Synced ${dispatched}/${visitors.length}…`);
    }
    await sleep(DELAY_MS);
  }

  // sendMetaEvent is fire-and-forget — let the last in-flight requests finish
  // before the process exits. Per-event delivery is logged by metaCapi above.
  console.log('All dispatched — waiting a few seconds for in-flight requests to drain…');
  await sleep(5000);
  console.log(`Sync complete! Dispatched ${dispatched} FindLocation events. ` +
              `Verify in Events Manager → Dataset (FindLocation, Action Source = Physical store).`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => { console.error('✗ sync-old-visits failed:', err.message); process.exit(1); });
