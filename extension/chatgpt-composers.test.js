// chatgpt.com serves two apps depending on the session and the viewport width: the
// desktop one, and the one behind the `/unauth-mweb/…` routes. Their composers have
// nothing in common — measured on both pages on 2026-09-15, composer filled in, the
// only state where the send button exists. These cases pin that each branch recognises
// its OWN composer and ignores the other.
import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import './adapters.js';
const A = globalThis.MilvagoAdapters;
const adapter = A.resolve('https://chatgpt.com/');

// The classes on both pages are generated (`x9r1u3d x1ob73xo …`): nothing usable,
// which is why the branches key off an identifier or `type` instead.
const desktop = `<form>
  <div id="prompt-textarea" contenteditable="true" class="ProseMirror"></div>
  <button data-testid="composer-plus-btn" type="button" aria-label="Ajouter des fichiers et plus encore"></button>
  <button data-testid="send-button" type="button" aria-label="Envoyer le message"></button>
</form>`;
const mobile = `<form>
  <textarea id="mobile-composer-prompt" class="x489bqi xibpbqy"></textarea>
  <button type="button" aria-label="Démarrage de la saisie vocale" class="x9r1u3d"></button>
  <button type="submit" aria-label="Envoyer un message" class="xxyica1"></button>
</form>
<form><button type="submit" aria-label="Rechercher"></button></form>`;

const page = markup => new JSDOM(markup, { url: 'https://chatgpt.com/' }).window.document;

test('each composer of chatgpt.com is recognised by its own branch', () => {
  const bureau = page(desktop);
  assert.equal(bureau.querySelectorAll(adapter.editor).length, 1);
  assert.equal(bureau.querySelectorAll(adapter.send).length, 1);
  assert.equal(bureau.querySelector(adapter.send).dataset.testid, 'send-button');

  const mobileDoc = page(mobile);
  assert.equal(mobileDoc.querySelectorAll(adapter.editor).length, 1);
  assert.equal(mobileDoc.querySelector(adapter.editor).id, 'mobile-composer-prompt');
  // A single button, the composer's own: the other form on the page also carries a
  // `type="submit"`, and that is exactly what the `:has()` rules out. Without it,
  // `submissionTarget` would refuse the ambiguity and silently give up.
  assert.equal(mobileDoc.querySelectorAll(adapter.send).length, 1);
  assert.equal(mobileDoc.querySelector(adapter.send).getAttribute('aria-label'), 'Envoyer un message');
});

test('an Enter in the mobile composer is a recognised submission', () => {
  const document = page(mobile);
  const editor = document.querySelector('#mobile-composer-prompt');
  // An empty composer is not a submission: `submission()` requires text, which is the
  // actual state at the moment the person confirms.
  editor.value = 'Test 3';
  const event = { type: 'keydown', key: 'Enter', isTrusted: true, isComposing: false, defaultPrevented: false, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, target: editor };
  assert.equal(A.submission(adapter, event, document), editor);
  const intent = A.submissionTarget(adapter, event, editor, document);
  assert.ok(intent, 'the submission must resolve a control to replay');
  assert.equal(intent.control.getAttribute('aria-label'), 'Envoyer un message');
});

test('a click on the mobile send control resolves the same submission', () => {
  const document = page(mobile);
  const editor = document.querySelector('#mobile-composer-prompt');
  editor.value = 'Test 3';
  const control = document.querySelector('#mobile-composer-prompt ~ button[type="submit"]');
  const event = { type: 'click', isTrusted: true, isComposing: false, defaultPrevented: false, target: control };
  assert.equal(A.submission(adapter, event, document), editor);
  assert.equal(A.submissionTarget(adapter, event, editor, document).control, control);
});

test('the branches stay language independent', () => {
  // A branch that names a translated label only works for one language: that is the
  // bug that left a provider silent in French. Both send branches key off a test
  // identifier and a structure instead.
  for (const branch of adapter.send.split(',')) {assert.ok(!/aria-label|title=/.test(branch), branch);}
  for (const branch of adapter.editor.split(',')) {assert.ok(!/aria-label|title=/.test(branch), branch);}
});

// Measured 2026-10-16 on the signed-in page: no `#prompt-textarea`, no `data-testid` anywhere
// on the composer, a bare ProseMirror textbox and a language-dependent send label.
const proseMirror = `<form><div data-composer-body="">
  <div contenteditable="true" role="textbox" class="ProseMirror" data-composer-markdown=""></div>
  <textarea hidden style="display:none">x</textarea>
  <button type="button" aria-label="Ajouter des fichiers et plus encore"></button>
  <button type="submit" aria-label="Envoyer" class="bg-composer-primary"></button>
</div></form>`;

test('the id-less ProseMirror composer and its send button are recognised', () => {
  const document = page(proseMirror);
  assert.equal(document.querySelectorAll(adapter.editor).length, 1);
  assert.equal(document.querySelector(adapter.editor).getAttribute('role'), 'textbox');
  assert.equal(document.querySelectorAll(adapter.send).length, 1);
  const editor = document.querySelector(adapter.editor);
  editor.textContent = 'Test 4';
  const event = { type: 'keydown', key: 'Enter', isTrusted: true, isComposing: false, defaultPrevented: false, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, target: editor };
  assert.equal(A.submission(adapter, event, document), editor);
  assert.equal(A.submissionTarget(adapter, event, editor, document).control.getAttribute('aria-label'), 'Envoyer');
});

// Desktop composer measured by CDP on 2026-10-16 (nothing sent, every non-GET request failed): the
// send control is a `type="submit"` without test id nor id, inside the composer body, the last button
// of the form, and exists only with a draft; dictation and voice are `type="button"`. A submit of the
// form outside the composer body is not the send, whatever its label.
const measured = `<form>
  <button type="submit" aria-label="Synthetic other action"></button>
  <div data-composer-body="">
    <div class="ProseMirror" contenteditable="true" data-composer-markdown="">x</div>
    <div data-composer-footer-responsive="">
      <button type="button" aria-label="Ajouter des fichiers et plus encore"></button>
      <button type="button" aria-label="Dicter"></button>
      <div class="ms-2"><button type="submit" aria-label="Envoyer"></button></div>
    </div>
  </div>
</form>`;
test('the desktop send control is the composer submit, not any submit of its form', async () => {
  const { factoryCatalog } = await import('./detection-factory.js');
  for (const [label, catalog] of [['factory', null], ['catalog', factoryCatalog]]) {
    A.applyCatalog(catalog);
    try {
      const chat = A.resolve('https://chatgpt.com/'), document = page(measured), editor = document.querySelector('.ProseMirror');
      assert.deepEqual([...document.querySelectorAll(chat.send)].map(b => b.getAttribute('aria-label')), ['Envoyer'], label);
      const enter = { type: 'keydown', key: 'Enter', isTrusted: true, isComposing: false, defaultPrevented: false, shiftKey: false, ctrlKey: false, altKey: false, metaKey: false, target: editor };
      assert.equal(A.submissionTarget(chat, enter, editor, document).control.getAttribute('aria-label'), 'Envoyer', label);
      const other = { type: 'click', isTrusted: true, defaultPrevented: false, target: document.querySelector('[aria-label="Synthetic other action"]') };
      assert.equal(A.submission(chat, other, document), null, label + ': another submit of the form is not a send');
    } finally { A.applyCatalog(null); }
  }
});
