// A selector keyed only on a translated label is broken for everyone who does not use
// the interface in that language.
//
// Found the hard way on 2026-09-14: Gemini's send selector was
// `button.send-button,button[aria-label="Send message"]`. The class sat on the wrapper
// rather than on the button, and the other branch was English — so on a French
// interface it matched nothing, and Gemini reported neither prompt nor response since
// the beginning. Worse, the failure is silent and total: `capture.js` gates response
// capture on a correlation, which only exists once a submission was intercepted, so one
// dead send selector switches off the whole provider.
//
// The product ships in four languages. A selector that enumerates labels can therefore
// only ever be a fallback; at least one branch must hold whatever the language is —
// a structural path, or a test identifier the provider exposes.
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
const A = globalThis.MilvagoAdapters;

// Branches that do not depend on the interface language: a test identifier, or plain
// structure. A branch naming aria-label, title, or visible text does depend on it.
const localized = branch => /aria-label\s*=|title\s*=|:has-text|::?contains/i.test(branch);
const independent = selector => selector.split(',').some(branch => !localized(branch));

// Known gaps, each with its reason. This list may shrink, never grow: a new provider
// must ship at least one language-independent branch, measured on the real page.
// None is corrected here: no replacement has been measured on the real page, and
// guessing one is exactly what produced the Gemini bug.
// Empty since 2026-09-14: every send selector was measured on its real page, composer
// filled, and replaced by a structural one — `button[data-testid="chat-input-send"]` for
// claude, `button[type="submit"]` for notebooklm, `button[data-testid="chat-submit"]` for
// grok. Perplexity was the one provider with no structural handle at all — no test
// identifier, no type="submit", no stable class — and its interface language follows the
// browser across dozens of languages, so enumerating labels could never hold. Its three
// DOM selectors are neutralised together instead (`:not(*)`), and it is observed through
// its network rule alone; a neutralised selector is language-independent by construction,
// so it does not belong here either.
const gaps = {};

test('every send selector holds whatever the interface language is', () => {
  const failing = A.adapters.filter(a => !independent(a.send)).map(a => a.id);
  assert.deepEqual(
    failing.sort(),
    Object.keys(gaps).sort(),
    'a provider gained or lost a language-dependent send selector: measure the page, then update the gap list',
  );
  for (const [id, selector] of Object.entries(gaps)) {
    assert.equal(A.adapters.find(a => a.id === id)?.send, selector, 'the recorded gap no longer matches the adapter');
  }
});

test('the editor and response selectors hold too', () => {
  for (const adapter of A.adapters) {
    assert.ok(independent(adapter.editor), `${adapter.id}: editor selector depends on the interface language`);
    assert.ok(independent(adapter.response), `${adapter.id}: response selector depends on the interface language`);
  }
});

test("Gemini's send selector reaches the button inside its wrapper", () => {
  // The exact shape that was measured on the page, and the exact mistake to guard:
  // the class belongs to the wrapper, so `button.send-button` matches nothing.
  const gemini = A.adapters.find(a => a.id === 'gemini');
  assert.equal(gemini.send, '.send-button button');
  assert.ok(!/button\.send-button/.test(gemini.send), 'the class sits on the wrapper, not on the button');
});
