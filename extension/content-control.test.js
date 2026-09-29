// What content control lets through, on the routes actually measured on
// 2026-09-15 in a HAR of chatgpt.com.
//
// Until now, enabling masking sealed ALL of the provider's traffic, document included:
// the site would not open, no content script was there to explain why, and
// the send rewritten by inspection was cancelled like the others — masking had
// therefore never masked anything. The guard is not lifted, it is placed where the data
// passes: what carries a prompt only leaves if its text is the one the agent just approved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { managedBridge } from './managed-fixture.js';

const policyFor = config => ({
  version: 3, revision: 1, expires_at: '2099-01-01T00:00:00Z',
  config: { services: [], collection: { enabled: false }, model_access: [], ...config },
});
let serial = 0;
// The approvals these tests obtain through `submit` are a MANAGED path: without
// a pin, masking refuses (fail-closed). The harness therefore pins the installation and
// replies with the broker's signed protocol.
async function worker(initial) {
  let policy = initial, message;
  const handlers = {}, stored = {}, noop = { addListener() {} };
  const bridge = managedBridge({
    browser_policy: () => ({ online: true, policy }),
    browser_inspect: req => ({ ok: true, action: 'observe', text: req.text, labels: [] }),
    browser_submit: req => ({ ok: true, action: 'observe', text: req.text, recording_required: false }),
    browser_event: req => ({ ok: true, id: crypto.randomUUID(), durable: true, delivery_id: req.delivery_id }),
    browser_catalog: () => ({ catalog: null, revision: 0, catalog_state: 'missing' }),
    browser_health: req => ({ accepted_health_ids: [req.batch.id] }),
  });
  globalThis.chrome = {
    runtime: { onInstalled: noop, onStartup: noop, onMessage: { addListener(fn) { message = fn; } }, sendNativeMessage: bridge.sendNativeMessage },
    storage: { managed: { async get() { return { milvago_pin: JSON.stringify(bridge.pin) }; } }, local: { async get(k) { return { [k]: stored[k] }; }, async set(value) { Object.assign(stored, value); } } },
    alarms: { create() {}, onAlarm: noop },
    tabs: { async query() { return [{ id: 1, url: 'https://chatgpt.com/' }]; }, async reload() {}, async sendMessage() {} },
    declarativeNetRequest: { async getDynamicRules() { return []; }, async updateDynamicRules() {} },
    webRequest: Object.fromEntries(['onBeforeRequest', 'onBeforeSendHeaders', 'onCompleted', 'onErrorOccurred'].map(k => [k, { addListener(fn) { handlers[k] = fn; } }])),
  };
  await import('./background.js?content-control=' + serial++);
  const send = (msg, sender = {}) => new Promise(resolve => message(msg, sender, resolve));
  assert.deepEqual(await send({ type: 'refresh' }), { ok: true });
  return { handlers, send, close() { delete globalThis.chrome; } };
}

const masking = policyFor({ privacy: { enabled: true } });
const uploads = policyFor({ protection: { block_uploads: true } });
const post = (over = {}) => ({ requestId: 'r' + serial++, tabId: 1, documentId: 'document-1', method: 'POST', type: 'xmlhttprequest', url: 'https://chatgpt.com/unauth-mweb/conversation/updates', ...over });
// The measured shape of the disconnected send: a form, which the synchronous path can read.
const form = text => ({ formData: { prompt: [text], conversationState: ['{"messages":[]}'] } });
const json = value => ({ raw: [{ bytes: new TextEncoder().encode(JSON.stringify(value)).buffer }] });
// A compressed body stays unreadable in a blocking handler, which is synchronous:
// this is the case for claude.ai.
const gzipped = { raw: [{ bytes: new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3]).buffer }] };
const allowed = (state, details) => !state.handlers.onBeforeRequest(details).cancel;
async function approve(state, text, page = 'https://chatgpt.com/') {
  const reply = await state.send({ type: 'submit', text, upload: false, event: { kind: 'prompt', action: 'observed', characters: text.length, labels: [], url: page } },
    { frameId: 0, documentId: 'document-1', tab: { id: 1 }, url: page });
  assert.equal(reply.ok, true, 'the inspection must have succeeded for an approval to exist');
}

test('the page loads under masking, and its Referer never leaves with it', async () => {
  const state = await worker(masking);
  try {
    const root = { requestId: 'nav', tabId: 1, method: 'GET', type: 'main_frame', url: 'https://chatgpt.com/' };
    assert.equal(allowed(state, root), true, 'without the page there is nothing left to mask');
    const headers = state.handlers.onBeforeSendHeaders({ ...root, requestHeaders: [
      { name: 'Referer', value: 'https://intranet.example.test/CONFIDENTIEL' },
      { name: 'Cookie', value: 'session=synthetic' },
    ] });
    assert.deepEqual(headers.requestHeaders.map(h => h.name), ['Cookie'], 'the Referer is what would leak an internal URL');

    // A sub-resource passes in every case (product decision of 2026-09-16: only
    // what carries a prompt is sealed); coming from the provider's page AND going to it
    // now only decides whether the `Referer` is stripped.
    const asset = { requestId: 'a1', tabId: 1, method: 'GET', type: 'script', url: 'https://chatgpt.com/unauth-mweb/assets/app.js' };
    assert.equal(allowed(state, { ...asset, initiator: 'https://chatgpt.com' }), true);
    assert.equal(allowed(state, { ...asset, requestId: 'a2' }), true);
    assert.equal(allowed(state, { requestId: 'a3', tabId: 1, method: 'GET', type: 'xmlhttprequest', url: 'https://exfil.test/DONNEES-CLIENT', initiator: 'https://chatgpt.com' }), true, 'une destination tierce sans prompt passe');
    // Product decision of 2026-09-16: a navigation to the covered provider
    // passes, whatever its path — otherwise `/login` was sealed and the site could
    // no longer be opened. It passes, but never with its `Referer`: the header
    // guard strips it here too, on the real handlers.
    const deep = { requestId: 'n2', tabId: 1, method: 'GET', type: 'main_frame', url: 'https://chatgpt.com/login' };
    assert.equal(allowed(state, deep), true);
    assert.deepEqual(state.handlers.onBeforeSendHeaders({ ...deep, requestHeaders: [
      { name: 'Referer', value: 'https://intranet.example.test/CONFIDENTIEL' },
      { name: 'Cookie', value: 'session=synthetic' },
    ] }).requestHeaders.map(h => h.name), ['Cookie'], 'un chemin autorisé ne rend pas le Referer');
    assert.equal(allowed(state, { requestId: 'n3', tabId: 1, method: 'GET', type: 'main_frame', url: 'https://chatgpt.com/?q=SYNTHETIQUE' }), true);
    // The third-party destination, on the other hand, stays sealed whatever the type.
    // A navigation to a third party from the covered page is no longer sealed (product
    // decision of 2026-09-16): it carries no prompt.
    assert.equal(allowed(state, { requestId: 'n4', tabId: 1, method: 'GET', type: 'main_frame', url: 'https://exfil.test/DONNEES-CLIENT', initiator: 'https://chatgpt.com' }), true);
  } finally { state.close(); }
});

test('a send leaves only with the text the agent approved, and only once', async () => {
  const state = await worker(masking);
  try {
    assert.equal(allowed(state, post({ requestBody: form('Test 3') })), false, 'nothing is approved yet');
    await approve(state, 'Test 3');
    assert.equal(allowed(state, post({ requestBody: form('Test 3') })), true);
    // The approval is consumed: replaying the same request does not pass again.
    assert.equal(allowed(state, post({ requestBody: form('Test 3') })), false, 'an approval serves once');
    await approve(state, 'Test 3');
    // The text rewritten after inspection is no longer the one that was approved.
    assert.equal(allowed(state, post({ requestBody: form('Test 3 et le numéro de carte') })), false);
  } finally { state.close(); }
});

test('an approval belongs to the tab and the document that obtained it', async () => {
  const state = await worker(masking);
  try {
    await approve(state, 'Test 3');
    assert.equal(allowed(state, post({ requestBody: form('Test 3'), tabId: 2 })), false, 'another tab');
    assert.equal(allowed(state, post({ requestBody: form('Test 3'), documentId: 'document-2' })), false, 'another document');
    assert.equal(allowed(state, post({ requestBody: form('Test 3') })), true, 'the one that obtained it');
  } finally { state.close(); }
});

test('a body this path cannot read leaves only inside the approval window', async () => {
  const state = await worker(masking);
  try {
    const compressed = () => post({ url: 'https://claude.ai/api/organizations/o/chat_conversations/c/completion', requestBody: gzipped });
    assert.equal(allowed(state, compressed()), false, 'unreadable and unapproved is refused');
    // An approval obtained on one provider does not authorize another: the text
    // inspected on ChatGPT says nothing about what would leave for Claude.
    await approve(state, 'Test 3');
    assert.equal(allowed(state, compressed()), false, 'an approval does not cross providers');
    await approve(state, 'Test 3', 'https://claude.ai/');
    assert.equal(allowed(state, compressed()), true);
    assert.equal(allowed(state, compressed()), false, 'the window closes behind it');
  } finally { state.close(); }
});

test('a body shaped like a prompt is held to the same rule, route known or not', async () => {
  const state = await worker(masking);
  try {
    // No rule describes this route; its body, though, has the shape of a send.
    const unknown = () => post({ url: 'https://chatgpt.com/backend-api/未知', requestBody: json({ messages: [{ content: 'secret' }], model: 'gpt' }) });
    assert.equal(allowed(state, unknown()), false);
    // The provider's ancillary traffic does not have this shape and passes: without it, ChatGPT
    // does not even build the send we want to control.
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com/backend-api/sentinel/req', requestBody: json({ p: 'synthetic' }) })), true);
  } finally { state.close(); }
});

// The second gate recomputes the decision when nothing is pending, and without the body:
// a send that is not an `xmlhttprequest` used to pass the first gate and then get sealed by the
// second. Fail-closed, but both must say the same thing about the same request,
// otherwise the provider's telemetry dies without anything explaining why.
test('both gates say the same thing of the same request, whatever its resource type', async () => {
  const state = await worker(masking);
  try {
    for (const type of ['xmlhttprequest', 'ping', 'other', 'beacon']) {
      const details = post({ requestId: 'g-' + type, type, url: 'https://chatgpt.com/unauth-mweb/events/business', requestBody: json({ telemetry: 'synthetic', at: 1 }) });
      const first = !state.handlers.onBeforeRequest(details).cancel;
      const second = !state.handlers.onBeforeSendHeaders({ ...details, requestBody: undefined, requestHeaders: [{ name: 'Content-Type', value: 'application/json' }] }).cancel;
      assert.equal(first, true, type + ' : la première garde laisse passer un envoi qui ne porte pas de prompt');
      assert.equal(second, first, type + ' : les deux gardes se contredisent');
    }
  } finally { state.close(); }
});

test('blocking file sends seals the file routes, and only them', async () => {
  const state = await worker(uploads);
  try {
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com/unauth-mweb/image-uploads', requestBody: json({}) })), false);
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com/file-synthetic', method: 'PUT', requestBody: json({}) })), false);
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com/unauth-mweb/image-uploads/process', requestBody: json({}) })), false);
    // The promise is "no file leaves", not "the service is cut off".
    assert.equal(allowed(state, post({ requestBody: form('Test 3') })), true);
  } finally { state.close(); }
});

// Measured on signed-out chatgpt.com in Chrome, 2026-09-29: the page's
// `image-normalization-worker` reserves the file with `POST /backend-anon/files`, puts the
// bytes to `files08.oaiusercontent.com/file-…` with the signed address it got back, then
// calls `POST /backend-anon/files/process_upload_stream`. The routes measured on 2026-09-15
// were no longer used: under upload blocking the image went through.
test('blocking file sends seals the signed-out upload the worker makes today', async () => {
  const state = await worker(uploads);
  try {
    const fromWorker = over => post({ tabId: 1, type: 'xmlhttprequest', initiator: 'https://chatgpt.com', requestBody: json({}), ...over });
    assert.equal(allowed(state, fromWorker({ url: 'https://chatgpt.com/backend-anon/files' })), false, 'the reservation carries the file name and yields the upload address');
    assert.equal(allowed(state, fromWorker({ url: 'https://chatgpt.com/backend-anon/files/process_upload_stream' })), false);
    // The send that only references an attachment still goes out: its text is not a file.
    assert.equal(allowed(state, post({ requestBody: form('Test image') })), true);
  } finally { state.close(); }
  const open = await worker(policyFor({ protection: { block_uploads: false } }));
  try {
    assert.equal(allowed(open, post({ url: 'https://chatgpt.com/backend-anon/files', initiator: 'https://chatgpt.com', requestBody: json({}) })), true, 'without the setting, an upload is only observed');
  } finally { open.close(); }
});

// `new URL('https://api.anthropic.com./').hostname` keeps the trailing dot, which DNS and TLS
// ignore: without a single canonical form, these hosts had neither a platform, nor a decision, nor a trace.
test('a trailing-dot hostname is the same covered host, not a way around the guard', async () => {
  const state = await worker(masking);
  try {
    assert.equal(allowed(state, post({ url: 'https://api.anthropic.com./v1/messages', initiator: 'https://claude.ai', requestBody: json({ model: 'synthetic', messages: [] }) })), false, 'direct API under masking');
    assert.equal(allowed(state, post({ url: 'https://api.openai.com./v1/responses', requestBody: json({ model: 'synthetic', input: 'x' }) })), false, 'direct API from anywhere');
    assert.equal(allowed(state, post({ url: 'https://API.ANTHROPIC.COM../v1/messages', requestBody: json({ model: 'synthetic', messages: [] }) })), false, 'several dots, any case');
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com./unauth-mweb/conversation/updates', requestBody: form('Test 3') })), false, 'prompt route without approval');
    await approve(state, 'Test 3');
    assert.equal(allowed(state, post({ url: 'https://chatgpt.com./unauth-mweb/conversation/updates', requestBody: form('Test 3 et autre chose') })), false, 'the approval still binds the text');
  } finally { state.close(); }
});

// Past 64 approved sends waiting on their headers, only the oldest is
// forgotten: clearing the whole set used to seal sends that were already approved and masked.
test('a full approved set evicts its oldest entry, never every approved send', async () => {
  const state = await worker(masking);
  try {
    const sent = [];
    for (let i = 0; i < 65; i++) {
      await approve(state, 'Test ' + i);
      const request = post({ requestBody: form('Test ' + i) });
      assert.equal(allowed(state, request), true);
      sent.push(request);
    }
    const headers = request => !state.handlers.onBeforeSendHeaders({ ...request, requestBody: undefined, requestHeaders: [] })?.cancel;
    assert.equal(headers(sent[0]), false, 'the oldest is the one forgotten, and it fails closed');
    assert.equal(headers(sent[1]), true);
    assert.equal(headers(sent[64]), true);
  } finally { state.close(); }
});
