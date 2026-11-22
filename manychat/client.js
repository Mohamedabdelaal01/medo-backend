// manychat/client.js — Factory that returns the active ManyChat client
// Real client is intentionally not implemented yet; flip MANYCHAT_MODE to real
// once the API key + endpoint URLs are available.

const mockClient = require('./mockClient');
const realClient = require('./realClient');
const demoClient = require('./demoClient');
const { getDb, isDemoContext } = require('../db');

function getManyChatClient() {
  // Phase 0: a demo_ session never reaches ManyChat, whatever its DB holds.
  if (isDemoContext()) return demoClient;
  const db = getDb();
  const apiKeyRow = db.prepare(`SELECT value FROM settings WHERE key = 'manychat_api_key'`).get();
  
  if (apiKeyRow && apiKeyRow.value && apiKeyRow.value.trim() !== '') {
    return realClient;
  }
  
  return mockClient;
}

module.exports = { getManyChatClient };
