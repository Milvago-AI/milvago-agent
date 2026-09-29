// Anonymous/mobile ChatGPT does not send JSON: its send request is
// `application/x-www-form-urlencoded`, which Chrome puts in `requestBody.formData`.
// The engine used to reject this path outright, so the request was unreadable even with the
// right rule — recorded in a real HAR on 2026-09-15, where the only send request is
// `POST /unauth-mweb/conversation/updates`, never `/backend-api/f/conversation`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { observeRequest, decodeBody, unwrapFields } from './detection.js';

const here = dirname(fileURLToPath(import.meta.url));
const catalog = JSON.parse(await readFile(join(here, 'detection-factory.json'), 'utf8'));
const rule = catalog.providers.find(p => p.id === 'chatgpt').network.find(n => n.path === '/unauth-mweb/conversation/updates');

// The measured shape: the fields are already decoded by Chrome, and two of them
// carry a full JSON document.
const attachments = JSON.stringify([{ fileId: 'file-synthetic', height: 1024, mimeType: 'image/jpeg', name: 'synthetic-drawing.jpg', size: 115104, width: 1024 }]);
const form = (fields = {}) => ({
  requestId: 'a', tabId: 1, documentId: 'document', frameId: 0, method: 'POST',
  url: 'https://chatgpt.com/unauth-mweb/conversation/updates',
  requestBody: { formData: Object.fromEntries(Object.entries({
    conversationState: JSON.stringify({ backendConversationId: '6aa99383-dd04-83ea-88fb-50a164a3820d', messages: [], userMessageCount: 1 }),
    imageAttachments: attachments,
    prompt: 'Test 3',
    ...fields,
  }).map(([key, value]) => [key, [value]])) },
});

test('the mobile send is observed: its text, its attachment and its conversation', async () => {
  const hit = await observeRequest(form(), catalog, true);
  assert.ok(hit, 'the form-encoded send must be observed at all');
  assert.equal(hit.provider.id, 'chatgpt');
  assert.equal(hit.characters, 6);
  assert.equal(hit.characters_known, true);
  assert.deepEqual(hit.files, ['synthetic-drawing.jpg'], 'the request is the only place naming the file here');
  assert.equal(hit.conversation_id, '6aa99383-dd04-83ea-88fb-50a164a3820d');
  // Chrome hands over decoded fields, not the bytes that left: claiming a size would
  // be inventing one.
  assert.equal(hit.body_bytes, null);
  // This route states no model, and an empty field is the correct answer here.
  assert.equal(hit.model, undefined);
});

test('a field is unwrapped because the rule names it, never because it looks like JSON', async () => {
  // A prompt that happens to be JSON is still text: that is exactly why
  // fields are named rather than trying to deserialize every value.
  const hit = await observeRequest(form({ prompt: '{"question":"synthetic"}' }), catalog, true);
  assert.equal(hit.characters, 24);
  assert.equal(hit.characters_known, true);
  // And without the name in the rule, the field stays the string it is.
  const body = unwrapFields({ imageAttachments: attachments }, []);
  assert.equal(typeof body.imageAttachments, 'string');
  assert.equal(typeof unwrapFields({ imageAttachments: attachments }, ['imageAttachments']).imageAttachments[0].name, 'string');
});

test('an unwrapped field never reaches the prototype', () => {
  const body = unwrapFields({ __proto__: '{"polluted":true}', prompt: 'x' }, ['__proto__', 'constructor']);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(body), Object.prototype);
});

test('a form body states what it carries, and refuses what it cannot name', async () => {
  const { body, body_bytes } = await decodeBody({ requestBody: { formData: { prompt: ['Test 3'], 'a[b]': ['ignored'], repeated: ['one', 'two'] } } });
  assert.deepEqual(body, { prompt: 'Test 3', repeated: ['one', 'two'] }, 'a key no catalogue path could name is not exposed');
  assert.equal(body_bytes, null);
  // A read error is still an absence of observation, not an empty body.
  assert.deepEqual(await decodeBody({ requestBody: { error: 'unreadable', formData: { prompt: ['x'] } } }), { body: null, body_bytes: null });
});

test('the desktop route keeps reading JSON bodies as before', async () => {
  const body = { messages: [{ content: { content_type: 'multimodal_text', parts: [{ content_type: 'image_asset_pointer' }, 'Analyse ce document'] } }], model: 'auto' };
  const hit = await observeRequest({
    requestId: 'b', tabId: 1, documentId: 'document', frameId: 0, method: 'POST',
    url: 'https://chatgpt.com/backend-api/f/conversation',
    requestBody: { raw: [{ bytes: new TextEncoder().encode(JSON.stringify(body)).buffer }] },
  }, catalog, true);
  assert.equal(hit.characters, 19);
  assert.equal(hit.model, 'auto');
  assert.deepEqual(hit.files, [], 'this rule names no file path, so it reports none');
});

test('the two chatgpt rules never match the same request', () => {
  const rules = catalog.providers.find(p => p.id === 'chatgpt').network;
  assert.deepEqual(rules.filter(n => (n.kind || 'prompt') === 'prompt').map(n => n.path), ['/backend-api/f/conversation', '/unauth-mweb/conversation/updates']);
  // Upload routes live in the same list and observe nothing: they
  // would render a request event with zero characters.
  // The last two were measured on 2026-09-29: signed-out uploads now go through the
  // page's image-normalization worker.
  assert.deepEqual(rules.filter(n => n.kind === 'file').map(n => n.path), ['/unauth-mweb/image-uploads', '/file-*', '/unauth-mweb/image-uploads/process', '/backend-anon/files', '/backend-anon/files/process_upload_stream']);
  // `observeRequest` drops all observation when two rules match: two
  // disjoint paths, so there is never ambiguity on the same request.
  assert.equal(rule.text_path, 'prompt');
  assert.deepEqual(rule.json_fields, ['imageAttachments', 'conversationState']);
});
