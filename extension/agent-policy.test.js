// Contract between the agent's IPC answer and the extension.
//
// The IPC endpoint is reachable by every signed-in local user, so the agent no
// longer answers `policy_v3` with the whole signed policy: watched keywords,
// exceptions, custom masking expressions, classification lists and the block
// message stay on the device. These tests pin the reduced shape the agent emits
// (endpoint/src/native.rs, `browser_policy`) and prove the extension still
// decides correctly from it — in particular that redacting the keyword *terms*
// while keeping their count does not weaken content control.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validPolicy, networkRules, eventForPolicy } from './policy.js';
import { contentControl, requestDecision } from './model-access.js';

// Exactly what `browser_policy` produces: no protection.exceptions, no
// protection.message, no privacy.types, no privacy.custom_rules, no
// classification, and keyword entries replaced by nulls.
function agentAnswer({ services = [], collection = { enabled: true, store_content: false }, protection = {}, privacyEnabled = false, modelAccess } = {}) {
  const config = {
    services,
    collection,
    protection: {
      block_uploads: protection.block_uploads ?? false,
      exact: protection.exact ?? 'observe',
      unicode: protection.unicode ?? 'observe',
      fuzzy: protection.fuzzy ?? 'off',
      keywords: Array.from({ length: protection.keywords ?? 0 }, () => null),
    },
    privacy: { enabled: privacyEnabled },
  };
  if (modelAccess !== undefined) {config.model_access = modelAccess;}
  return { version: 3, revision: 7, issued_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', config };
}

test('the reduced agent answer is still a valid policy', () => {
  assert.ok(validPolicy(agentAnswer()));
  assert.ok(validPolicy(agentAnswer({ modelAccess: [] })));
});

test('service restrictions survive the reduction', () => {
  const policy = agentAnswer({ services: [{ id: 'chatgpt', enabled: true, mode: 'block', domains: ['chatgpt.com'] }] });
  const domains = networkRules(policy).flatMap(r => r.condition.requestDomains);
  assert.ok(domains.includes('chatgpt.com'));
  assert.ok(domains.includes('api.openai.com'));
});

test('a redacted keyword list still forces content control', () => {
  // The extension only ever used the count, never the terms.
  assert.equal(contentControl(agentAnswer({ protection: { keywords: 3, exact: 'block' } })), true);
  assert.equal(contentControl(agentAnswer({ protection: { keywords: 3, exact: 'observe', unicode: 'observe', fuzzy: 'off' } })), false);
  assert.equal(contentControl(agentAnswer({ protection: { keywords: 0, exact: 'block' } })), false);
  assert.equal(contentControl(agentAnswer({ privacyEnabled: true })), true);
  assert.equal(contentControl(agentAnswer({ protection: { block_uploads: true } })), true);
});

test('content control still refuses an unqualified API request', () => {
  const policy = agentAnswer({
    services: [{ id: 'chatgpt', enabled: true, mode: 'observe', domains: ['chatgpt.com'] }],
    protection: { keywords: 2, exact: 'block' },
    modelAccess: [],
  });
  const decision = requestDecision({ url: 'https://api.openai.com/v1/responses', type: 'xmlhttprequest', method: 'POST' }, policy);
  assert.equal(decision?.reason, 'control_unavailable');
});

test('collection switches survive the reduction', () => {
  const services = [{ id: 'chatgpt', enabled: true, mode: 'observe', domains: ['chatgpt.com'] }];
  const stored = eventForPolicy(
    { kind: 'prompt', action: 'observed', characters: 4, labels: [], prompt: 'test' },
    'https://chatgpt.com/c/00000000-0000-4000-8000-000000000000',
    'chrome',
    agentAnswer({ services, collection: { enabled: true, store_content: true } }),
  );
  assert.equal(stored.prompt, 'test');
  const withheld = eventForPolicy(
    { kind: 'prompt', action: 'observed', characters: 4, labels: [], prompt: 'test' },
    'https://chatgpt.com/c/00000000-0000-4000-8000-000000000000',
    'chrome',
    agentAnswer({ services, collection: { enabled: true, store_content: false } }),
  );
  assert.equal(withheld.prompt, undefined);
});

test('attachment names travel only while the policy asks for them', () => {
  const services = [{ id: 'chatgpt', enabled: true, mode: 'observe', domains: ['chatgpt.com'] }];
  const url = 'https://chatgpt.com/c/00000000-0000-4000-8000-000000000000';
  const input = { kind: 'prompt', action: 'observed', characters: 4, labels: [], files: ['rapport.pdf', 'notes.txt'] };
  const off = eventForPolicy(input, url, 'chrome', agentAnswer({ services, collection: { enabled: true, store_content: false, store_file_names: false } }));
  assert.equal(off.files, undefined);
  const on = eventForPolicy(input, url, 'chrome', agentAnswer({ services, collection: { enabled: true, store_content: false, store_file_names: true } }));
  assert.deepEqual(on.files, ['rapport.pdf', 'notes.txt']);
});

test('a page cannot smuggle anything through the attachment names', () => {
  const services = [{ id: 'chatgpt', enabled: true, mode: 'observe', domains: ['chatgpt.com'] }];
  const url = 'https://chatgpt.com/c/00000000-0000-4000-8000-000000000000';
  const policy = agentAnswer({ services, collection: { enabled: true, store_content: false, store_file_names: true } });
  const hostile = eventForPolicy(
    { kind: 'prompt', action: 'observed', characters: 4, labels: [], files: ['ok.pdf', 'line\nbreak.txt', '', 'x'.repeat(201), 42, ...Array.from({ length: 30 }, (_, i) => `f${i}.txt`)] },
    url, 'chrome', policy,
  );
  assert.equal(hostile.files.length, 20);
  assert.ok(hostile.files.every(name => typeof name === 'string' && name.length > 0 && name.length <= 200 && !name.includes('\n')));
  // Names belong to a request, never to a navigation or a response.
  const navigation = eventForPolicy({ kind: 'navigation', action: 'observed', characters: 0, labels: [], files: ['ok.pdf'] }, url, 'chrome', policy);
  assert.equal(navigation.files, undefined);
});
