// Real campaign 0.7.3: a Lexical editor ignored the masked draft written by `insertText`
// right after the selection moved (it reads the selection on `selectionchange`, fired later),
// and drops line breaks from `insertText`; a plain-text paste keeps them. Measured by CDP on a
// real Lexical composer (2026-10-16). The editor below is a synthetic stand-in.
import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import './adapters.js';
const A = globalThis.MilvagoAdapters;

function lexical({ paste = true } = {}) {
  const { window } = new JSDOM('<div contenteditable="true">Bonjour 4111 1111 1111 1111</div>');
  const doc = window.document, editor = doc.querySelector('div');
  let seen = false;
  window.DataTransfer = class { #data = {}; setData(k, v) { this.#data[k] = v; } getData(k) { return this.#data[k] ?? ''; } };
  window.ClipboardEvent = class extends window.Event { constructor(type, init) { super(type, init); this.clipboardData = init.clipboardData; } };
  // Like Lexical: the selection counts once the browser has announced it, later.
  doc.addEventListener('selectionchange', () => { seen = true; });
  const select = window.Selection.prototype.addRange;
  window.Selection.prototype.addRange = function (range) { seen = false; select.call(this, range); };
  doc.execCommand = (command, _, text) => { if (command === 'insertText' && seen) { editor.textContent = text.replaceAll('\n', ''); } return true; };
  if (paste) { editor.addEventListener('paste', event => { if (seen) { event.preventDefault(); editor.textContent = event.clipboardData.getData('text/plain'); } }); }
  return editor;
}

test('the draft is written once the editor has seen the selection', async () => {
  assert.equal(await A.write(lexical(), 'Bonjour [CARD]'), 'Bonjour [CARD]');
});

test('a multi-line draft the editor flattens is written as a plain-text paste', async () => {
  assert.equal(await A.write(lexical(), 'ligne une\nligne deux [IBAN]'), 'ligne une\nligne deux [IBAN]');
});

test('an editor that takes neither leaves the send refused', async () => {
  assert.equal(await A.write(lexical({ paste: false }), 'ligne une\nligne deux [IBAN]'), null);
});

// Measured on a real rich editor (2026-10-17): it lets an untrusted paste go without inserting anything,
// but an `insertText` in the same task then loses its line breaks. Synthetic stand-in below.
test('a paste the editor lets go is followed by an insertion that keeps its line breaks', async () => {
  const { window } = new JSDOM('<div contenteditable="true"></div>');
  const doc = window.document, editor = doc.querySelector('div');
  let pasting = false;
  window.DataTransfer = class { #data = {}; setData(k, v) { this.#data[k] = v; } getData(k) { return this.#data[k] ?? ''; } };
  window.ClipboardEvent = class extends window.Event { constructor(type, init) { super(type, init); this.clipboardData = init.clipboardData; } };
  editor.addEventListener('paste', () => { pasting = true; window.setTimeout(() => { pasting = false; }, 0); });
  doc.execCommand = (command, _, text) => {
    if (command !== 'insertText') { return false; }
    editor.replaceChildren(...(pasting ? [text.replaceAll('\n', '')] : text.split('\n')).map(line => { const p = doc.createElement('p'); p.textContent = line; return p; }));
    return true;
  };
  assert.equal(await A.insert(editor, 'ligne une\nligne deux'), true);
  assert.deepEqual([...editor.querySelectorAll('p')].map(p => p.textContent), ['ligne une', 'ligne deux']);
});
