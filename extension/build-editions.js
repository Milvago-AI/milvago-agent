// Assembles the two extension packages from this single source tree.
//
//   endpoint/extension-community   Chromium, historical identity, no model control
//   endpoint/extension-enterprise  Chromium, its own identity, model control
//   endpoint/extension-firefox-<edition>  the Gecko variant of each
//
// Four things differ per edition: which module answers the per-model questions
// (model-rules.js or its Community stub), the package identity, the Community
// signature in capture.js, and the providers covered -- Community qualifies ChatGPT
// and Claude only, so its package carries neither the selectors, nor the factory
// catalogue entries, nor the content-script matches of any other site. Everything
// else stays byte-identical, so the two builds cannot drift apart silently.
import { mkdir, copyFile, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { editionProviders, factoryModule, restrictFactory, restrictAdapters, restrictMatches, communitySignature } from './editions.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const firefoxVersion = (await readFile(join(here, 'firefox-version.txt'), 'utf8')).trim();
if (!/^\d+\.\d+\.\d+$/.test(firefoxVersion)) {throw new Error('Invalid Firefox release version');}
const ports = JSON.parse(await readFile(join(root, 'extension-ports.json'), 'utf8'));
const shared = ['milvago-symbol-256.png', 'managed-schema.json', 'adapters.js', 'detection.js', 'detection-factory.js', 'detection-runtime.js', 'model-access.js', 'background.js', 'broker.js', 'capture.js', 'policy.js', 'popup.html', 'popup.css', 'popup.js'];

const factory = JSON.parse(await readFile(join(here, 'detection-factory.json'), 'utf8'));
await writeFile(join(here, 'detection-factory.js'), factoryModule(factory, null));

const editions = {
  community: { rules: 'model-rules.js', key: 'extension-key.txt', id: 'extension-id.txt', gecko: 'browser-community@milvago.app' },
};

async function read(name) {
  return (await readFile(join(root, name), 'utf8')).trim();
}

async function copyShared(destination, overrides) {
  for (const file of shared) {
    if (file in overrides) {await writeFile(join(destination, file), overrides[file]);}
    else {await copyFile(join(here, file), join(destination, file));}
  }
}

for (const [edition, spec] of Object.entries(editions)) {
  const manifest = JSON.parse(await readFile(join(here, 'manifest.json'), 'utf8'));
  manifest.key = await read(spec.key);
  const channel = edition === 'enterprise' ? 'commercial' : 'community';
  manifest.update_url = `http://127.0.0.1:${ports[channel]}/ext/update.xml`;
  const identity = await read(spec.id);

  const overrides = {};
  if (edition === 'community') {overrides['capture.js'] = communitySignature(await readFile(join(here, 'capture.js'), 'utf8'));}
  const allowed = editionProviders[edition];
  if (allowed) {
    const restricted = restrictAdapters(await readFile(join(here, 'adapters.js'), 'utf8'), allowed);
    overrides['adapters.js'] = restricted.source;
    overrides['detection-factory.js'] = factoryModule(restrictFactory(factory, allowed), allowed);
    manifest.content_scripts[0].matches = restrictMatches(manifest.content_scripts[0].matches, restricted.hosts);
  }

  const chromium = join(root, `extension-${edition}`);
  await mkdir(chromium, { recursive: true });
  await writeFile(join(chromium, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  await copyShared(chromium, overrides);
  // The edition's rule module always lands under the shared name the imports use.
  await copyFile(join(here, spec.rules), join(chromium, 'model-rules.js'));
  await writeFile(join(chromium, 'extension-id.txt'), identity + '\n');
  await writeFile(join(chromium, 'extension-firefox-id.txt'), spec.gecko + '\n');

  const gecko = structuredClone(manifest);
  gecko.version = firefoxVersion;
  delete gecko.key;
  // Firefox uses its native managed-storage manifest and rejects managed_schema.
  delete gecko.storage;
  // The Mozilla-signed package is served by the agent's independent TLS listener.
  delete gecko.update_url;
  gecko.background = { scripts: ['background.js'], type: 'module' };
  gecko.browser_specific_settings = {
    gecko: {
      id: spec.gecko,
      update_url: `https://127.0.0.1:${ports['firefox_' + channel]}/ext/updates.json`,
      strict_min_version: '140.0',
      data_collection_permissions: { required: ['browsingActivity', 'websiteActivity', 'websiteContent', 'personalCommunications'] },
    },
  };
  const firefox = join(root, `extension-firefox-${edition}`);
  await mkdir(firefox, { recursive: true });
  await writeFile(join(firefox, 'manifest.json'), JSON.stringify(gecko, null, 2) + '\n');
  await copyShared(firefox, overrides);
  await copyFile(join(here, spec.rules), join(firefox, 'model-rules.js'));

  console.log(`${edition}: chromium ${identity}, gecko ${spec.gecko}, rules ${spec.rules}, providers ${allowed ? allowed.join('+') : 'all'}`);
}
