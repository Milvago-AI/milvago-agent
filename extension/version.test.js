import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

test('manifest and package expose one extension version',async()=>{
  const [manifestText,packageText]=await Promise.all([
    readFile(new URL('./manifest.json',import.meta.url),'utf8'),
    readFile(new URL('./package.json',import.meta.url),'utf8'),
  ]);
  const manifest=JSON.parse(manifestText);
  const packageManifest=JSON.parse(packageText);
  assert.match(manifest.version,/^\d+\.\d+\.\d+$/);
  assert.equal(packageManifest.version,manifest.version);
});
