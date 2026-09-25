// The navigation emitted when a provider finally names the conversation in its URL
// must still carry the correlation of the exchange that opened it.
//
// This is a contract with the server, not a local detail: the conversation grouping
// bridges correlation to conversation through the one record that carries both. On
// ChatGPT the conversation identifier only exists from the second message onwards, so
// without this navigation the opening exchange would be stranded in a thread of its
// own. Nothing in the capture code said so out loud, and nothing failed if it changed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { webcrypto } from 'node:crypto';
// The content script reads its API namespace once, at load.
globalThis.chrome = { storage: { local: { async get() { return {}; }, async set() {} } } };
await import('./adapters.js');
await import('./capture.js');
const { eventForPolicy } = await import('./policy.js');
const A = globalThis.MilvagoAdapters;

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const thread = '/c/00000000-0000-4000-8000-000000000000';
const policy = {
  version: 2, revision: 9, expires_at: '2099-01-01T00:00:00Z',
  config: { collection: { enabled: true, store_content: false }, services: A.adapters.map(a => ({ id: a.id, domains: [a.domain], enabled: true, mode: 'observe' })) },
};
const trusted = (type, target) => ({ type, target, isTrusted: true, preventDefault() {}, stopImmediatePropagation() {} });

async function open() {
  const dom = new JSDOM('<form><textarea id="prompt-textarea"></textarea><button data-testid="send-button">Send</button></form>', { url: 'https://chatgpt.com/' });
  // The durable receipt is bound to a digest of the prompt; without it the capture
  // stops before it records the correlation, and jsdom ships no SubtleCrypto.
  Object.defineProperty(dom.window.crypto, 'subtle', { value: webcrypto.subtle });
  const doc = dom.window.document, messages = [];
  const controller = globalThis.MilvagoCapture.start(doc, dom.window.location, async msg => {
    messages.push(msg);
    if (msg.type === 'policy') {return { ok: true, policy };}
    if (msg.type === 'inspect') {return { ok: true, action: 'observe', text: msg.text, labels: [] };}
    if (msg.type === 'submit') {return { ok: true, action: 'observe', text: msg.text, durable: true, recording_required: true, authority: null, delivery_id: '00000000-0000-4000-8000-000000000001' };}
    return { ok: true };
  });
  await delay(5);
  return {
    controller, doc, dom, messages,
    navigations: () => messages.filter(m => m.type === 'event' && m.event.kind === 'navigation').map(m => m.event),
    submits: () => messages.filter(m => m.type === 'submit').map(m => m.event),
    close() { controller.dispose(); dom.window.close(); },
  };
}

test('the navigation that names the conversation keeps the opening exchange attached', async () => {
  const f = await open();
  try {
    // The thread starts with no identifier at all: the page is the bare provider.
    assert.equal(f.navigations().length, 1);
    assert.equal(f.navigations()[0].correlation_id, undefined);

    A.write(f.doc.querySelector('#prompt-textarea'), 'Synthetic prompt');
    await f.controller.handle(trusted('click', f.doc.querySelector('[data-testid="send-button"]')));
    const opening = f.submits()[0]?.correlation_id;
    assert.match(opening || '', /^[0-9a-f-]{36}$/, 'the opening exchange must have a correlation');

    // The provider assigns the URL once the exchange exists.
    f.dom.reconfigure({ url: 'https://chatgpt.com' + thread });
    f.controller.navigation();
    await delay(5);

    // The document sends the correlation and the URL it is actually on; the provider
    // and the conversation identifier are derived from that URL by eventForPolicy, so
    // the record that reaches the server carries both.
    assert.equal(A.context(f.dom.window.location.href).conversation_id, '00000000-0000-4000-8000-000000000000');
    assert.equal(f.navigations().length, 2, 'the assignment must produce a navigation');
    assert.equal(f.navigations().at(-1).correlation_id, opening, 'the navigation must carry it, or the server cannot bridge them');
  } finally { f.close(); }
});

test('an ordinary move between conversations carries no stale correlation', async () => {
  const f = await open();
  try {
    A.write(f.doc.querySelector('#prompt-textarea'), 'Synthetic prompt');
    await f.controller.handle(trusted('click', f.doc.querySelector('[data-testid="send-button"]')));
    f.dom.reconfigure({ url: 'https://chatgpt.com' + thread });
    f.controller.navigation();
    await delay(5);

    // Leaving for another thread is not an assignment: carrying the correlation on
    // would attach an exchange to a conversation it never belonged to.
    f.dom.reconfigure({ url: 'https://chatgpt.com/c/11111111-1111-4111-8111-111111111111' });
    f.controller.navigation();
    await delay(5);

    assert.equal(A.context(f.dom.window.location.href).conversation_id, '11111111-1111-4111-8111-111111111111');
    assert.equal(f.navigations().length, 3, 'the move must produce its own navigation');
    assert.equal(f.navigations().at(-1).correlation_id, undefined);
  } finally { f.close(); }
});

// Measured on claude.ai on 2026-09-15: the worker was handed `sender.url =
// https://claude.ai/new` while the tab was on `/chat/98ec1ab5-...`, on six messages out
// of six. `sender.url` is the URL the document was COMMITTED at, and not one of these
// providers reloads when the conversation changes. Deriving the identifier from it gave
// two symptoms of one defect: a tab committed on `/new` recorded no identifier at all,
// and a tab committed on `/chat/<id>` stamped that first identifier onto every later
// conversation. The document is the only party that knows where it is now.
test('the record carries the URL the document is on, not the one its frame was committed at', async () => {
  const f = await open();
  try {
    A.write(f.doc.querySelector('#prompt-textarea'), 'Synthetic prompt');
    await f.controller.handle(trusted('click', f.doc.querySelector('[data-testid="send-button"]')));
    f.dom.reconfigure({ url: 'https://chatgpt.com' + thread });
    f.controller.navigation();
    await delay(5);

    const navigation = f.navigations().at(-1);
    assert.equal(navigation.url, 'https://chatgpt.com' + thread, 'the document must report where it is');
    assert.equal(f.submits()[0].url, 'https://chatgpt.com/', 'a submission reports it too');

    // The frame is still committed at the bare origin, as it is on the real sites.
    const stale = 'https://chatgpt.com/';
    const event = eventForPolicy(navigation, stale, 'chrome', policy);
    assert.equal(event.conversation_id, '00000000-0000-4000-8000-000000000000');
    assert.equal(event.url, 'https://chatgpt.com' + thread);

    // A document may only ever speak about its own provider: naming another one falls
    // back to the frame, so a compromised page cannot attribute its traffic elsewhere.
    const spoofed = eventForPolicy({ ...navigation, url: 'https://claude.ai/chat/11111111-1111-4111-8111-111111111111' }, stale, 'chrome', policy);
    assert.equal(spoofed.provider, 'chatgpt.com');
    assert.equal(spoofed.conversation_id, undefined);
    assert.equal(spoofed.url, 'https://chatgpt.com');

    // A malformed URL is not a way to suppress the frame's own context either.
    assert.equal(eventForPolicy({ ...navigation, url: 'not a url' }, stale, 'chrome', policy).provider, 'chatgpt.com');
  } finally { f.close(); }
});

// An attached file leaves for the provider as soon as it is attached, so it is recorded
// then -- before the text, and before the conversation exists. Measured on chatgpt.com on
// 2026-09-15: that record carried no correlation at all on the first message of a thread,
// and the console showed the attachment as a conversation of its own. The composition now
// has its own correlation, minted at the attachment and reused by the text that follows.
test('an attachment joins the exchange it belongs to, not a thread of its own', async () => {
  const f = await open();
  const store = policy.config.collection.store_file_names;
  policy.config.collection.store_file_names = true;
  try {
    const input = f.doc.createElement('input');
    input.type = 'file';
    f.doc.body.appendChild(input);
    // jsdom exposes no way to fill a FileList; the capture only reads `length`, the
    // items by index and their `name`, never a byte.
    const files = [{ name: 'synthetic-document.png' }];
    Object.defineProperty(input, 'files', { value: files });

    await f.controller.upload(trusted('change', input));
    const attachment = f.submits().at(-1);
    assert.deepEqual(attachment.files, ['synthetic-document.png'], 'the attachment must be recorded');
    assert.match(attachment.correlation_id || '', /^[0-9a-f-]{36}$/, 'an attachment must open a correlation');

    A.write(f.doc.querySelector('#prompt-textarea'), 'Analyse ce document');
    await f.controller.handle(trusted('click', f.doc.querySelector('[data-testid="send-button"]')));
    const sent = f.submits().at(-1);
    assert.equal(sent.characters, 19, 'the text submission must be the one measured');
    assert.equal(sent.correlation_id, attachment.correlation_id, 'the text must reuse the correlation the attachment opened');
    assert.deepEqual(sent.files, ['synthetic-document.png'], 'and still name the file it carries');

    // The next composition is a new exchange: reusing the correlation would glue two
    // separate sends together.
    A.write(f.doc.querySelector('#prompt-textarea'), 'Et celui-ci ?');
    await f.controller.handle(trusted('click', f.doc.querySelector('[data-testid="send-button"]')));
    assert.notEqual(f.submits().at(-1).correlation_id, sent.correlation_id);
  } finally { policy.config.collection.store_file_names = store; f.close(); }
});
