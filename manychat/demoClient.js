// manychat/demoClient.js — the ManyChat client of a demo_ session (phase 0).
// Answers like the mock (a training visit-confirm or sale still reads «sent»
// and the 24 h window reads open) but makes NO request and logs no id: the
// demo DB is a clone of production with real customers' ManyChat ids.
const { blockInDemo } = require('../services/outbound');

function skipped(action) {
  blockInDemo(`manychat.${action}`);
  return { ok: true, mocked: true, skipped: 'demo' };
}

const demoClient = {
  mode: 'demo',
  async getInfo() {
    blockInDemo('manychat.getInfo');
    return { ok: true, last_interaction: new Date(Date.now() - 3600e3).toISOString(),
      ig_last_interaction: null, error: null, skipped: 'demo' };
  },
  async sendFlow()       { return skipped('sendFlow'); },
  async setCustomField() { return skipped('setCustomField'); },
  async addTag()         { return skipped('addTag'); },
  async removeTag()      { return skipped('removeTag'); },
};

module.exports = demoClient;
