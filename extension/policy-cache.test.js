// Service availability and server reachability are independent.
import test from 'node:test';
import assert from 'node:assert/strict';

const signedPolicy = (revision = 4) => ({
  version: 3,
  revision,
  expires_at: '2099-01-01T00:00:00Z',
  config: {
    collection: { enabled: true, store_content: false },
    services: [{ id: 'chatgpt', domains: ['chatgpt.com'], enabled: true, mode: 'block', redirect_url: '' }],
    model_access: [],
  },
});

// Each test loads its own module instance: the worker's top-level code is the
// thing under test, and it runs once per start.
function environment({ answer, stored = {}, tabs = [] }) {
  const state = { stored: { ...stored }, rules: [], reloaded: [], installed: undefined, reads: [] };
  const noop = { addListener() {} };
  globalThis.chrome = {
    runtime: {
      onInstalled: { addListener(fn) { state.installed = fn; } },
      onStartup: noop,
      onMessage: { addListener(fn) { state.message ??= fn; } },
      async sendNativeMessage(_host, message) { return answer(message); },
    },
    alarms: { create() {}, onAlarm: { addListener(fn) { state.alarm = fn; } } },
    tabs: {
      async query() { return tabs; },
      async sendMessage() {},
      async reload(id) { state.reloaded.push(id); },
    },
    storage: {
      local: {
        async get(key) { state.reads.push(key); return key in state.stored ? { [key]: state.stored[key] } : {}; },
        async set(value) { Object.assign(state.stored, value); },
      },
    },
    declarativeNetRequest: {
      async getDynamicRules() { return state.rules; },
      async updateDynamicRules({ addRules }) { state.rules = addRules; },
    },
  };
  return state;
}

const settle = async () => { for (let i = 0; i < 50; i++) {await new Promise(r => setTimeout(r, 1));} };
const sealed = rules => rules.some(rule => rule.id >= 20000);

// Since 2026-09-16, the policy is no longer written to storage.local at all:
// this cleartext cache was removed. These tests keep the same guarantee — a dead
// agent or a refusal seals — and prove that the key is neither written nor read.
test('a successful refresh never writes the policy to local storage', async () => {
  const state = environment({ answer: message => message.op === 'policy_v3' ? { ok: true, online: true, policy: signedPolicy() } : { ok: true } });
  await import('./background.js?case=persists');
  state.installed({ reason: 'install' });
  await settle();
  assert.ok(!('policy' in state.stored), 'the signed policy must not be cached in clear');
  assert.ok(!state.reads.includes('policy'), 'the policy key must not even be read');
  assert.equal(state.stored.status.connected, true);
  delete globalThis.chrome;
});

test('a stopped service seals even with a previously cached policy', async () => {
  const state = environment({
    answer: () => ({ok:false,error:'agent_unavailable'}),
    stored: {policy:signedPolicy(7)},
  });
  await import('./background.js?case=unreachable');
  await settle();
  assert.ok(sealed(state.rules));
  assert.equal(state.stored.status.connected,false);
  // A value left behind by an older version is neither read nor erased: it is
  // inert, and the seal proves it.
  assert.deepEqual(state.stored.policy,signedPolicy(7));
  assert.ok(!state.reads.includes('policy'));
  delete globalThis.chrome;
});
test('an offline server keeps the policy supplied by the live local service', async () => {
  const state = environment({answer: message => message.op === 'policy_v3'
    ? {ok:true,online:false,policy:signedPolicy(7)} : {ok:true}});
  await import('./background.js?case=server-offline');
  await settle();
  assert.ok(!sealed(state.rules));
  assert.equal(state.stored.status.connected,true);
  assert.equal(state.stored.status.online,false);
  assert.equal(state.stored.status.revision,7);
  delete globalThis.chrome;
});

test('a refused policy seals the covered surface without touching any cached value', async () => {
  const state = environment({
    answer: () => ({ ok: false, error: 'operation_refused' }),
    stored: { policy: signedPolicy(7) },
  });
  await import('./background.js?case=refused');
  state.installed({ reason: 'install' });
  await settle();
  assert.ok(sealed(state.rules), 'a refusal did not seal the covered surface');
  assert.ok(!state.reads.includes('policy'), 'a cached policy must not be read');
  delete globalThis.chrome;
});

test('an expired cached policy is never applied', async () => {
  const expired = { ...signedPolicy(9), expires_at: '2000-01-01T00:00:00Z' };
  const state = environment({ answer: () => ({ ok: false, error: 'agent_unavailable' }), stored: { policy: expired } });
  await import('./background.js?case=expired');
  state.installed({ reason: 'install' });
  await settle();
  assert.ok(sealed(state.rules), 'an expired cached policy was accepted');
  assert.ok(!state.reads.includes('policy'));
  delete globalThis.chrome;
});

// Product decision of 2026-09-22: two refreshes lost to slowness are
// tolerated, the third one seals; any other failure seals immediately.
test('two slow refreshes keep the policy, the third seals', async () => {
  let slow = false;
  const state = environment({ answer: message => {
    if (message.op !== 'policy_v3') {return { ok: true };}
    if (slow) {throw new Error('broker response expired');}
    return { ok: true, online: true, policy: signedPolicy() };
  } });
  await import('./background.js?case=slow');
  await settle();
  assert.ok(!sealed(state.rules));
  slow = true;
  for (const round of [1, 2]) {
    state.alarm({ name: 'policy' }); await settle();
    assert.ok(!sealed(state.rules), `slow refresh ${round} sealed`);
    assert.equal(state.stored.status.connected, true);
  }
  state.alarm({ name: 'policy' }); await settle();
  assert.ok(sealed(state.rules), 'third slow refresh did not seal');
  assert.equal(state.stored.status.connected, false);
  delete globalThis.chrome;
});
test('a refusal after a valid policy seals at once', async () => {
  let refuse = false;
  const state = environment({ answer: message => message.op === 'policy_v3' && !refuse
    ? { ok: true, online: true, policy: signedPolicy() } : refuse ? { ok: false, error: 'operation_refused' } : { ok: true } });
  await import('./background.js?case=refusal-after-valid');
  await settle();
  refuse = true;
  state.alarm({ name: 'policy' }); await settle();
  assert.ok(sealed(state.rules));
  delete globalThis.chrome;
});
test('a policy refreshed moments ago serves the next page request without a new exchange', async () => {
  let polls = 0;
  const state = environment({ answer: message => {
    if (message.op === 'policy_v3') {polls++; return { ok: true, online: true, policy: signedPolicy() };}
    return { ok: true };
  } });
  await import('./background.js?case=reuse');
  await settle();
  const before = polls;
  const reply = await new Promise(resolve => state.message({ type: 'policy' }, { frameId: 0, tab: { id: 1 }, url: 'https://chatgpt.com/' }, resolve));
  assert.equal(reply.ok, true);
  assert.equal(polls, before, 'a fresh policy was fetched again');
  delete globalThis.chrome;
});

test('an extension update reloads the covered AI tabs', async () => {
  const state = environment({
    answer: message => message.op === 'policy_v3' ? { ok: true, online: true, policy: signedPolicy() } : { ok: true },
    tabs: [{ id: 11, url: 'https://chatgpt.com/' }, { id: 12, url: 'https://claude.ai/chat/abcdefgh' }, { id: 13, url: 'https://example.test/' }],
  });
  await import('./background.js?case=update');
  // A content script injected by the previous version has lost its channel to this
  // worker: without the reload, capture stops while the page still looks supervised.
  state.installed({ reason: 'update' });
  await settle();
  assert.deepEqual(state.reloaded.sort(), [11, 12]);
  delete globalThis.chrome;
});

test('an ordinary install does not reload anything', async () => {
  const state = environment({
    answer: message => message.op === 'policy_v3' ? { ok: true, online: true, policy: signedPolicy() } : { ok: true },
    tabs: [{ id: 11, url: 'https://chatgpt.com/' }],
  });
  await import('./background.js?case=install');
  state.installed({ reason: 'install' });
  await settle();
  assert.deepEqual(state.reloaded, []);
  delete globalThis.chrome;
});
