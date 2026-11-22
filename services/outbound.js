// services/outbound.js — no outgoing call from a demo_ session (phase 0).
//
// A demo_ training account works on a clone of production that holds real
// customers' ManyChat ids. Nothing it does may reach a customer, Meta or an
// AI provider. Two layers, both keyed on the request's DB context
// (db.isDemoContext — AsyncLocalStorage, so promises, timers and
// fire-and-forget sends started by the request keep it):
//   1. the clients refuse first, with a clean answer:
//        manychat/client.js  → the demo client (answers like the mock, sends nothing)
//        manychat/realClient → apiPost / apiGet return { ok:false, error:'demo' }
//        services/ai.js      → callAi returns { ok:false, unconfigured:true }
//        services/metaCapi   → sendMetaEvent / bulk sync return without a request
//   2. a backstop on globalThis.fetch: any fetch made in a demo context is
//      rejected before it leaves, whatever code made it.
// Each refusal is counted on /health (outbound_blocked_demo, by kind). No id,
// no phone, no URL is logged or counted.

const { isDemoContext } = require('../db');

const blocked = {};          // kind → n, since boot
function countBlocked(kind) {
  const k = String(kind || 'other').slice(0, 30);
  blocked[k] = (blocked[k] || 0) + 1;
}

// True when the caller must not make the outgoing call; counts it.
function blockInDemo(kind) {
  if (!isDemoContext()) return false;
  countBlocked(kind);
  return true;
}

let installed = false;
function installFetchGuard() {
  if (installed || typeof globalThis.fetch !== 'function') return;
  const inner = globalThis.fetch;
  const guarded = function demoGuardedFetch(...args) {
    if (isDemoContext()) {
      countBlocked('fetch');
      return Promise.reject(new Error('outbound_blocked_demo'));
    }
    return inner.apply(this, args);
  };
  guarded.__demoGuard = true;
  globalThis.fetch = guarded;
  installed = true;
}
installFetchGuard();

function blockedSnapshot() { return { ...blocked }; }

module.exports = { isDemoContext, blockInDemo, blockedSnapshot, installFetchGuard };
