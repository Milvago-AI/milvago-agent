// The model, the reasoning effort and the conversation identifier come from the
// outgoing request, never from the page.
//
// Measured on the real sites on 2026-09-14: claude.ai displays a localized composite
// ("Fable 5.1 Moyen" — model and effort fused, translated) and chatgpt.com exposes no
// identifiable model control at all, while the requests carry `claude-fable-5-1` with
// `effort`, `gpt-5-6` with `thinking_effort`, and ChatGPT's conversation identifier.
//
// They cannot ride the prompt: the submission path records it durably *before* the
// page is allowed to send, which is what makes content control enforceable and is not
// traded away for a metadata field. They are attributes of the exchange, so the
// service worker keeps what the last observed request of a tab said and attaches it to
// the response, which is the one event emitted after its own request.
import test from 'node:test';
import { pinAuthority } from './broker.js';
const pin = { installation: '00000000-0000-4000-8000-000000000021', edition: 'community', origin: 'https://instance.example.invalid', organization_anchor: 'synthetic-anchor', signing_key: 'synthetic-key' };
const authority = await pinAuthority(pin);
import assert from 'node:assert/strict';
import { detectionRuntime } from './detection-runtime.js';
import { observeRequest } from './detection.js';

const policy = { revision: 1, expires_at: '2099-01-01T00:00:00Z', config: { collection: { enabled: true }, discovery: { enabled: false }, services: [{ enabled: true, domains: ['ai.example.invalid'] }] } };
const rule = { host: 'ai.example.invalid', path: '/v1/chat', method: 'POST', text_path: 'prompt', model_path: 'model', effort_path: 'thinking_effort', conversation_path: 'conversation_id' };
const catalog = { providers: [{ id: 'synthetic', label: 'Synthetic', domains: ['ai.example.invalid'], aliases: [], network: [rule] }] };
const bytes = value => new TextEncoder().encode(JSON.stringify(value)).buffer;
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

function fixture() {
  const listeners = {}, calls = [], storage = {};
  globalThis.MilvagoAdapters = { resolve: () => ({ id: 'synthetic' }), applyCatalog: () => {} };
  const api = {
    runtime: { getManifest: () => ({ version: '0.5.8', content_scripts: [] }) },
    storage: { managed: { async get() { return { milvago_pin: JSON.stringify(pin) }; } }, local: { async get() { return structuredClone(storage); }, async set(value) { Object.assign(storage, structuredClone(value)); } } },
    // No document receipt: the network observation stands on its own and the pending
    // entries are flushed on their own schedule.
    tabs: { async sendMessage() { return { ok: true, delivery_id: null, authority }; } },
    webRequest: {
      onBeforeRequest: { addListener(l) { listeners.before = l; } },
      onHeadersReceived: { addListener(l) { listeners.headers = l; } },
      onErrorOccurred: { addListener(l) { listeners.error = l; } },
    },
  };
  const bridge = async request => {
    calls.push(structuredClone(request));
    if (request.op === 'catalog') {return { revision: 1, catalog_state: 'ok', catalog, expires_at: '2099-01-01T00:00:00Z' };}
    if (request.op === 'event_v2') {return { ok: true, durable: true, delivery_id: request.delivery_id, id: '00000000-0000-4000-8000-000000000022' };}
    if (request.op === 'event_receipt') {return { ok: true, durable: false, delivery_id: request.delivery_id };}
    if (request.op === 'detector_health') {return { accepted_health_ids: [request.batch.id] };}
    throw new Error('unexpected bridge operation ' + request.op);
  };
  return { runtime: detectionRuntime(api, bridge, 'firefox', () => policy), listeners, calls };
}

async function request(f, body, tabId = 7, requestId = 'r1') {
  f.listeners.before({ requestId, tabId, documentId: 'document-a', frameId: 0, method: 'POST', url: 'https://ai.example.invalid/v1/chat', requestBody: { raw: [{ bytes: bytes(body) }] } });
  f.listeners.headers({ requestId, statusCode: 200, responseHeaders: [{ name: 'content-type', value: 'application/json' }] });
  // Poll rather than count ticks: `decodeBody` can decompress the body through a
  // stream, which adds unpredictable asynchronous rounds. A fixed number of `tick()`
  // calls made the wait implementation-dependent and the suite order-dependent.
  for (let n = 0; n < 200 && !f.calls.some(call => call.q?.op === 'event_v2' || call.op === 'event_v2'); n++)
    {await new Promise(resolve => setImmediate(resolve));}
  await tick();
}

const event = (kind, extra = {}) => ({ provider: 'ai.example.invalid', source: 'browser', tool: 'firefox', kind, action: 'observed', characters: kind === 'navigation' ? 0 : 12, labels: [], ...extra });
const sender = (id = 7) => ({ url: 'https://ai.example.invalid/chat', tab: { id }, documentId: 'document-a' });
const delivered = f => f.calls.filter(c => c.op === 'event_v2').map(c => c.event);

test('the request names the exchange and the response carries it', async () => {
  const f = fixture();
  await f.runtime.refresh();
  await request(f, { prompt: 'synthetic', model: 'fixture-model-4', thinking_effort: 'extended', conversation_id: 'thread-77' });
  await f.runtime.dom(event('response'), sender(), {});
  await tick();
  const response = delivered(f).find(e => e.kind === 'response');
  assert.ok(response, 'the response must have been delivered');
  assert.equal(response.model, 'fixture-model-4');
  assert.equal(response.effort, 'extended');
  assert.equal(response.conversation_id, 'thread-77');
});

test('a prompt is never given what the tab last said', async () => {
  const f = fixture();
  await f.runtime.refresh();
  await request(f, { prompt: 'synthetic', model: 'fixture-model-4', thinking_effort: 'extended' });
  // A prompt is recorded before its own request leaves, so anything the tab already
  // said belongs to the previous exchange and must not be attributed to this one.
  await f.runtime.dom(event('prompt'), sender(), {});
  await tick();
  const prompt = delivered(f).find(e => e.kind === 'prompt' && e.characters === 12);
  assert.ok(prompt);
  assert.equal(prompt.model, undefined);
  assert.equal(prompt.effort, undefined);
});

test('what one tab said is never attributed to another', async () => {
  const f = fixture();
  await f.runtime.refresh();
  await request(f, { prompt: 'synthetic', model: 'fixture-model-4', thinking_effort: 'extended' }, 7);
  await f.runtime.dom(event('response'), sender(9), {});
  await tick();
  const response = delivered(f).find(e => e.kind === 'response');
  assert.ok(response);
  assert.equal(response.model, undefined);
  assert.equal(response.effort, undefined);
});

test('a mode change does not leave the previous effort behind', async () => {
  // Measured on ChatGPT: the identifier changes with the mode (`gpt-5-6` instant,
  // `gpt-5-6-thinking` extended) within one conversation, and the effort can simply
  // stop being stated. Keeping it would attribute it to an exchange that never asked.
  const f = fixture();
  await f.runtime.refresh();
  await request(f, { prompt: 'first', model: 'fixture-model-thinking', thinking_effort: 'extended', conversation_id: 'thread-77' }, 7, 'r1');
  await request(f, { prompt: 'second', model: 'fixture-model' }, 7, 'r2');
  await f.runtime.dom(event('response'), sender(), {});
  await tick();
  const response = delivered(f).find(e => e.kind === 'response');
  assert.ok(response);
  assert.equal(response.model, 'fixture-model');
  assert.equal(response.effort, undefined, 'the previous effort must not survive');
  // The conversation identifier does belong to the thread and survives a request
  // that does not restate it — a provider may only name it from the second message.
  assert.equal(response.conversation_id, 'thread-77');
});

test('an identifier the event already carries is never overwritten', async () => {
  const f = fixture();
  await f.runtime.refresh();
  await request(f, { prompt: 'synthetic', conversation_id: 'thread-from-request' });
  await f.runtime.dom(event('navigation', { conversation_id: 'thread-from-url' }), sender(), {});
  await tick();
  const navigation = delivered(f).find(e => e.kind === 'navigation');
  assert.ok(navigation);
  assert.equal(navigation.conversation_id, 'thread-from-url');
});

test('one route with two body shapes is read by candidate paths, in order', async () => {
  // Measured on Le Chat: the prompt is `content[*].text` when a thread opens and
  // `messageInput[*].text` afterwards, on the same route. Two rules cannot settle it,
  // so the rule names both and the first that yields text wins.
  const both = { providers: [{ ...catalog.providers[0], network: [{ ...rule, text_path: '', text_paths: ['messageInput[*].text', 'content[*].text'] }] }] };
  const details = body => ({ requestId: 'a', tabId: 1, documentId: 'd', method: 'POST', url: 'https://ai.example.invalid/v1/chat', requestBody: { raw: [{ bytes: bytes(body) }] } });

  const opening = await observeRequest(details({ content: [{ text: 'four' }] }), both, true);
  assert.equal(opening.characters, 4);
  assert.equal(opening.characters_known, true);

  const following = await observeRequest(details({ messageInput: [{ text: 'seventeen chars!!' }] }), both, true);
  assert.equal(following.characters, 17);

  // When both are present the order of the list decides, and nothing is concatenated.
  const ambiguous = await observeRequest(details({ messageInput: [{ text: 'aaa' }], content: [{ text: 'bbbbb' }] }), both, true);
  assert.equal(ambiguous.characters, 3);

  // No candidate matches: the measurement is declared unknown rather than invented.
  const silent = await observeRequest(details({ other: 'x' }), both, true);
  assert.equal(silent.characters_known, false);
  assert.equal(silent.characters, 0);

  // A rule that names a single path keeps working untouched.
  const single = await observeRequest(details({ prompt: 'six ch' }), catalog, true);
  assert.equal(single.characters, 6);
});

test('an ambiguous path reports nothing rather than a plausible wrong value', async () => {
  // Measured on Le Chat: the reasoning is stated by *adding* `beta-reasoning` to a
  // `features` array, not by a value at a path. An `effort_path` of `features[*]`
  // would report the first conforming string of the list — `beta-code-interpreter` —
  // which is plausible, wrong and silent. Ambiguity reports nothing instead.
  const membership = { providers: [{ ...catalog.providers[0], network: [{ ...rule, effort_path: 'features[*]' }] }] };
  const details = body => ({ requestId: 'a', tabId: 1, documentId: 'd', method: 'POST', url: 'https://ai.example.invalid/v1/chat', requestBody: { raw: [{ bytes: bytes(body) }] } });

  const several = await observeRequest(details({ prompt: 'x', features: ['beta-code-interpreter', 'beta-reasoning'] }), membership, true);
  assert.equal(several.effort, undefined, 'two candidates must not be resolved by order');

  // A list of one is not ambiguous: it is read.
  const single = await observeRequest(details({ prompt: 'x', features: ['beta-reasoning'] }), membership, true);
  assert.equal(single.effort, 'beta-reasoning');

  // The same rule applies to the model and the conversation, for the same reason.
  const models = { providers: [{ ...catalog.providers[0], network: [{ ...rule, model_path: 'messages[*].model', conversation_path: 'threads[*].id' }] }] };
  const ambiguous = await observeRequest(details({ prompt: 'x', messages: [{ model: 'model-a' }, { model: 'model-b' }], threads: [{ id: 'one' }, { id: 'two' }] }), models, true);
  assert.equal(ambiguous.model, undefined);
  assert.equal(ambiguous.conversation_id, undefined);
});

test('the effort is read from its own path and refused when it is not one', async () => {
  const details = body => ({ requestId: 'a', tabId: 1, documentId: 'd', method: 'POST', url: 'https://ai.example.invalid/v1/chat', requestBody: { raw: [{ bytes: bytes(body) }] } });
  const hit = await observeRequest(details({ prompt: 'x', model: 'fixture-model-4', thinking_effort: 'extended' }), catalog, true);
  assert.equal(hit.model, 'fixture-model-4');
  assert.equal(hit.effort, 'extended');

  // Not an effort: a free-form value must not reach the field.
  for (const value of ['Extended Thinking', 'x'.repeat(60), 42, '']) {
    assert.equal((await observeRequest(details({ prompt: 'x', thinking_effort: value }), catalog, true)).effort, undefined, JSON.stringify(value));
  }
  // The edition switch gates the effort exactly like the model.
  const gated = await observeRequest(details({ prompt: 'x', model: 'fixture-model-4', thinking_effort: 'extended' }), catalog, false);
  assert.equal(gated.model, undefined);
  assert.equal(gated.effort, undefined);
});
