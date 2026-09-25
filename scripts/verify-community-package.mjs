// What the Community edition covers, checked on the **assembled** package rather than on
// the source tree: a filtered path proves nothing about what a package contains.
//
// A `grep` of provider names would fail here on a correct package: the catalogue carries a
// `known_platforms` section — the mere *presence* of a platform, open to every edition —
// distinct from `providers[]`, which is *capture*. Naming a platform opens no capture;
// `providers[]`, `coveredProviders`, the adapters and the manifest matches do. The check is
// therefore structural, not lexical.
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const packageDirectory = join(root, 'extension-community');
const expected = ['chatgpt', 'claude'];
const failures = [];
const check = (name, ok, detail) => { if (!ok) failures.push(name + (detail ? ' — ' + detail : '')); else console.log('OK  ' + name + (detail ? ' — ' + detail : '')); };

const factorySource = await readFile(join(packageDirectory, 'detection-factory.js'), 'utf8');
const start = factorySource.indexOf('=', factorySource.indexOf('factoryCatalog')) + 1;
const end = factorySource.indexOf(';\nexport const coveredProviders');
if (start < 1 || end < 0) throw new Error('The assembled catalogue module is unreadable.');
const catalog = JSON.parse(factorySource.slice(start, end));
const covered = JSON.parse(factorySource.slice(factorySource.indexOf('[', end), factorySource.indexOf(';', end + 2)));

const captured = (catalog.providers ?? []).map(provider => provider.id).sort();
check('providers[]: capture limited to the edition', JSON.stringify(captured) === JSON.stringify(expected), captured.join(' ') || 'none');
check('coveredProviders: same list', JSON.stringify([...covered].sort((left, right) => expected.indexOf(left) - expected.indexOf(right))) === JSON.stringify(expected), covered.join(' '));

// `known_platforms` is not capture: the section is expected, whole.
check('known_platforms: presence kept', (catalog.known_platforms ?? []).length > 0, (catalog.known_platforms ?? []).length + ' entries');

const hosts = new Set((catalog.providers ?? []).flatMap(provider => [...(provider.domains ?? []), ...(provider.aliases ?? [])]));
const manifest = JSON.parse(await readFile(join(packageDirectory, 'manifest.json'), 'utf8'));
const matches = manifest.content_scripts?.[0]?.matches ?? [];
const stray = matches.filter(match => ![...hosts].some(host => match.includes(host)));
check('manifest: no content script outside the edition', stray.length === 0, stray.join(' ') || matches.length + ' matches');

const adapters = await readFile(join(packageDirectory, 'adapters.js'), 'utf8');
const adapterIds = [...adapters.matchAll(/^[ \t]{0,8}\['([a-z]+)','([^']+)'/gm)].map(entry => entry[1]);
check('adapters: one per covered provider', JSON.stringify([...new Set(adapterIds)].sort((left, right) => expected.indexOf(left) - expected.indexOf(right))) === JSON.stringify(expected), adapterIds.join(' '));

// The package never carries a per-model decision: its rules module is the Community stub.
const rules = await readFile(join(packageDirectory, 'model-rules.js'), 'utf8');
check('model rules: Community contract, no decision', /export const modelObservation\s*=\s*true/.test(rules) && !/allowlist|denylist/.test(rules));

if (failures.length) { console.error('\nFailed checks:\n- ' + failures.join('\n- ')); process.exit(1); }
console.log('\nCommunity package matches its edition.');
