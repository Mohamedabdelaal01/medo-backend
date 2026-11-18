// manychat/mockClient.js — In-memory ManyChat stub
// Logs every intended call. Swap to a real HTTP client when MANYCHAT_MODE=real.

function log(action, payload) {
  console.log(`[ManyChat MOCK] ${action}`, JSON.stringify(payload));
}

// getInfo's answer is settable (tests); default: the customer wrote 1 hour ago.
let mockInfo = null;

const mockClient = {
  mode: 'mock',
  setMockInfo(info) { mockInfo = info; },
  async getInfo({ user_id }) {
    log('getInfo', { user_id });
    if (mockInfo) return { ...mockInfo };
    return { ok: true, last_interaction: new Date(Date.now() - 3600e3).toISOString(),
      ig_last_interaction: null, error: null };
  },
  async sendFlow({ user_id, flow_id }) {
    log('sendFlow', { user_id, flow_id });
    return { ok: true, mocked: true };
  },
  async sendMessage({ user_id, text }) {
    log('sendMessage', { user_id, text });
    return { ok: true, mocked: true };
  },
  async setCustomField({ user_id, field, value }) {
    log('setCustomField', { user_id, field, value });
    return { ok: true, mocked: true };
  },
  async addTag({ user_id, tag }) {
    log('addTag', { user_id, tag });
    return { ok: true, mocked: true };
  },
  async removeTag({ user_id, tag }) {
    log('removeTag', { user_id, tag });
    return { ok: true, mocked: true };
  },
};

module.exports = mockClient;
