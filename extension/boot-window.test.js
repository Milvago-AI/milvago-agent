import test from 'node:test';
import assert from 'node:assert/strict';

// The MV3 worker is woken UP BY the request: the blocking handler is synchronous and
// runs before the first `refresh()` has returned a policy. The other tests
// wait for `stored` before exercising the handlers, so none of them reached this
// window — which is exactly why the defect stayed invisible in unit testing.
// Here the agent's response is held back by a gate, so the boot state is
// the one actually measured, not an assumed state.
test('the worker boot window passes reads and still seals every send', async () => {
 const handlers = {}, noop = { addListener() {} };
 let release, stored;
 const gate = new Promise(resolve => { release = resolve; });
 const policy = { version: 3, revision: 190, expires_at: '2099-01-01T00:00:00Z', config: { services: [], collection: { enabled: false }, model_access: [] } };
 globalThis.chrome = {
  runtime: {
   onInstalled: noop, onStartup: noop, onMessage: { addListener() {} },
   async sendNativeMessage(host, msg) { if (msg.op === 'policy_v3') { await gate; return { ok: true, online: true, policy }; } return { ok: true }; },
  },
  alarms: { create() {}, onAlarm: noop },
  tabs: { async query() { return []; }, async sendMessage() {}, async reload() {} },
  storage: { local: { async get() { return {}; }, async set(value) { stored = value; } } },
  declarativeNetRequest: { async getDynamicRules() { return []; }, async updateDynamicRules() {} },
  webRequest: Object.fromEntries(['onBeforeRequest', 'onBeforeSendHeaders', 'onCompleted', 'onErrorOccurred']
   .map(k => [k, { addListener(fn) { handlers[k] = fn; } }])),
 };
 await import('./background.js');
 try {
  // Boot window: the policy has not come back yet, the gate holds the agent.
  const navigation = { requestId: 'nav', url: 'https://claude.ai/login', method: 'GET', type: 'main_frame', tabId: 1 };
  assert.deepEqual(handlers.onBeforeRequest(navigation), {}, 'la navigation qui réveille le worker doit passer');
  assert.deepEqual(handlers.onBeforeSendHeaders({ ...navigation, requestHeaders: [] }), {}, 'la seconde garde doit s’accorder avec la première');

  const asset = { requestId: 'asset', url: 'https://claude.ai/app.js', method: 'GET', type: 'script', tabId: 1, initiator: 'https://claude.ai' };
  assert.deepEqual(handlers.onBeforeRequest(asset), {}, 'une sous-ressource du fournisseur lui-même doit passer');

  // What BELONGS to the provider without carrying its hostname must also pass. claude.ai
  // serves its UI from `assets-proxy.anthropic.com`: with an exact comparison,
  // its 54 scripts were being canceled during the wake-up window — so on EVERY
  // load, since the worker gets evicted at rest. The page stayed half-loaded even
  // with the content decision fixed. Measured on 2026-09-16 on a real capture.
  const owned = { requestId: 'owned', url: 'https://assets-proxy.anthropic.com/x.js', method: 'GET', type: 'script', tabId: 1, initiator: 'https://claude.ai' };
  assert.deepEqual(handlers.onBeforeRequest(owned), {}, 'un hôte d’assets du fournisseur doit passer au démarrage');
  const sub = { requestId: 'sub', url: 'https://cdn.claude.ai/x.js', method: 'GET', type: 'script', tabId: 1, initiator: 'https://claude.ai' };
  assert.deepEqual(handlers.onBeforeRequest(sub), {}, 'un sous-domaine du fournisseur doit passer au démarrage');

  // Nothing else passes: no prompt can leave without a check during the window.
  for (const [name, details] of [
   ['un envoi', { requestId: 'post', url: 'https://claude.ai/api/completion', method: 'POST', type: 'xmlhttprequest', tabId: 1, initiator: 'https://claude.ai' }],
   ['un xhr en GET', { requestId: 'xhr', url: 'https://claude.ai/api/me', method: 'GET', type: 'xmlhttprequest', tabId: 1, initiator: 'https://claude.ai' }],
   ['un GET vers un tiers', { requestId: 'third', url: 'https://cdn.example.test/a.js', method: 'GET', type: 'script', tabId: 1, initiator: 'https://claude.ai' }],
   ['une API directe', { requestId: 'api', url: 'https://api.anthropic.com/v1/messages', method: 'POST', type: 'xmlhttprequest', tabId: 1 }],
  ]) {assert.equal(handlers.onBeforeRequest(details).cancel, true, `${name} doit rester refusé au démarrage`);}

  // The window closes as soon as the first refresh lands.
  release();
  for (let i = 0; !stored && i < 200; i++) {await new Promise(r => setTimeout(r, 1));}
  assert.equal(stored.status.revision, 190, 'la politique doit être adoptée');
  assert.deepEqual(handlers.onBeforeRequest({ ...navigation, requestId: 'after' }), {}, 'hors contrôle de contenu la navigation reste libre');
 } finally { delete globalThis.chrome; }
});
