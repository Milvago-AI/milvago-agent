// Real campaign 0.7.3: a rich editor adds U+200B and U+200C to its draft. Read raw, they made
// the masked draft's read-back fail (nothing could be sent under masking) and counted two
// characters too many on every prompt. Synthetic drafts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import './adapters.js';
const A = globalThis.MilvagoAdapters;

test('a draft is read without its zero-width characters', () => {
  const { document } = new JSDOM('<div contenteditable="true">​Bonjour‌ le⁠ monde﻿</div><textarea></textarea>').window;
  assert.equal(A.read(document.querySelector('div')), 'Bonjour le monde');
  const area = document.querySelector('textarea');
  area.value = 'a​‌b';
  assert.equal(A.read(area), 'ab');
  // A joiner inside an emoji sequence is part of the character the person typed.
  area.value = 'famille \u{1f468}‍\u{1f469}';
  assert.equal(A.read(area), 'famille \u{1f468}‍\u{1f469}');
});

test('a masked draft is written back although the editor adds zero-width characters', async () => {
  const { document } = new JSDOM('<textarea></textarea>').window;
  const area = document.querySelector('textarea');
  area.addEventListener('input', () => { if (!area.value.endsWith('‌')) { area.value += '​‌'; } });
  assert.equal(await A.write(area, 'Bonjour [IBAN]'), 'Bonjour [IBAN]');
  assert.equal(A.layout('Bonjour​ [IBAN]‌'), A.layout('Bonjour [IBAN]'));
});
