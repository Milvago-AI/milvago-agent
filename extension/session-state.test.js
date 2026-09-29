// Signed-out ChatGPT, measured on 2026-09-29 in Firefox (HAR) and Chrome (CDP): the send
// goes through `POST /unauth-mweb/conversation/updates` and names no model anywhere, and
// the page then moves to `/uc/<id>` where an account uses `/c/<id>`. The catalogue states
// both facts on the measured route and provider; nothing here is read from the page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import './adapters.js';
import { observeRequest } from './detection.js';

const A = globalThis.MilvagoAdapters;
const here = dirname(fileURLToPath(import.meta.url));
const factory = JSON.parse(await readFile(join(here, 'detection-factory.json'), 'utf8'));
const chatgpt = factory.providers.find(p => p.id === 'chatgpt');
const route = chatgpt.network.find(n => n.path === '/unauth-mweb/conversation/updates');
const withRule = rule => ({ ...factory, providers: [{ ...chatgpt, network: [rule] }] });
const send = {
  requestId: 'a', tabId: 1, documentId: 'document', frameId: 0, method: 'POST',
  url: 'https://chatgpt.com/unauth-mweb/conversation/updates',
  requestBody: { formData: { prompt: ['Salut'], conversationState: [JSON.stringify({ messages: [], userMessageCount: 0 })] } },
};

test('the account state comes from the rule that matched the route', async () => {
  assert.equal((await observeRequest(send, withRule({ ...route, session: 'signed_out' }), true)).session, 'signed_out');
  assert.equal((await observeRequest(send, withRule(route), true)).session, undefined, 'a rule that states nothing reports nothing');
  assert.equal((await observeRequest(send, withRule({ ...route, session: 'anonymous' }), true)).session, undefined, 'outside the vocabulary reports nothing');
  // The body says `"mode":"anonymous"` too, but a body is not what decides.
  const claimed = structuredClone(send);
  claimed.requestBody.formData.session = ['signed_in'];
  assert.equal((await observeRequest(claimed, withRule({ ...route, session: 'signed_out' }), true)).session, 'signed_out');
});

test('a further conversation path recognizes the signed-out page and keeps its shape', () => {
  const id = '6abad4ee-1a3c-83ea-8ac0-5b28d9c18ff5';
  try {
    A.applyCatalog({ ...factory, providers: [{ ...chatgpt, conversation_paths: ['/uc/*'] }] });
    const signedOut = A.context(`https://chatgpt.com/uc/${id}`);
    assert.equal(signedOut.conversation_id, id);
    assert.equal(signedOut.url, `https://chatgpt.com/uc/${id}`);
    const signedIn = A.context(`https://chatgpt.com/c/${id}`);
    assert.equal(signedIn.conversation_id, id);
    assert.equal(signedIn.url, `https://chatgpt.com/c/${id}`);
    // Without the field, the page is not a conversation: exactly what was measured.
    A.applyCatalog({ ...factory, providers: [chatgpt] });
    assert.equal(A.context(`https://chatgpt.com/uc/${id}`).conversation_id, undefined);
  } finally {
    A.applyCatalog(null);
  }
});
