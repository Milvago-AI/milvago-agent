import { deepStrictEqual } from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { loadBrowserEngine } from "./wasm-loader.mjs";

const edition = process.argv[2] ?? "commercial";
if (!["community", "commercial"].includes(edition)) throw new Error("edition must be community or commercial");
const root = new URL(".", import.meta.url);
const fixtures = JSON.parse(await readFile(new URL("./fixtures/parity.json", root)));
const selected = fixtures.filter(item => item.editions.includes(edition));
const runner = spawnSync("cargo", ["run", "--quiet", "--manifest-path", "endpoint/browser-engine/Cargo.toml", "--target-dir", ".local/build/browser-engine-native-parity-" + edition, ...(edition === "commercial" ? ["--features", "sensitive-detection"] : []), "--bin", "inspect-fixtures", "--", "endpoint/browser-engine/fixtures/parity.json", edition], { encoding: "utf8" });
if (runner.status !== 0) throw new Error("native fixture runner failed: " + runner.stderr);
const native = JSON.parse(runner.stdout);
if (native.length !== selected.length) throw new Error("native runner did not construct every fixture");
const bytes = await readFile(new URL("./dist/" + edition + "/milvago-browser-engine.wasm", root));
const server = createServer((request, response) => {
  if (request.url !== "/engine.wasm") { response.writeHead(404).end(); return; }
  response.writeHead(200, { "content-type": "application/wasm" }).end(bytes);
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
try {
  const engine = await loadBrowserEngine(new URL("http://127.0.0.1:" + server.address().port + "/engine.wasm"));
  const actual = selected.map(item => {
    const input = structuredClone(item.input);
    if (input.text === "__OVER_LIMIT__") input.text = "x".repeat(32 * 1024 + 1);
    const raw = engine.inspectJson(JSON.stringify(input));
    const parsed = JSON.parse(raw);
    return parsed.ok === false && "error" in parsed
      ? { name: item.name, error: parsed.error }
      : { name: item.name, result: parsed };
  });
  deepStrictEqual(actual, native, "native/WASM result mismatch for " + edition);
  for (let i = 0; i < 32; i++) {
    const repeated = JSON.parse(engine.inspectJson(JSON.stringify(selected[0].input)));
    if (repeated.action !== "block") throw new Error("WASM allocation/free repeat failed");
  }
  const byName = Object.fromEntries(actual.map(item => [item.name, item]));
  for (const name of ["exact-block", "unicode-block", "fuzzy-block", "service-block", "upload-block"]) {
    if (byName[name]?.result?.action !== "block") throw new Error(name + " did not block");
  }
  if (byName["exception-skips-keyword"]?.result?.labels?.length !== 0) throw new Error("exception was ignored");
  if (byName.redirect?.result?.action !== "redirect") throw new Error("redirect was not retained");
  if (byName["text-limit"]?.error !== "text exceeds local inspection limit") throw new Error("32KiB boundary was not enforced");
  if (edition === "commercial") {
    if (byName["custom-redact-review"]?.result?.text !== "[custom]" || byName["custom-redact-review"]?.result?.action !== "review") throw new Error("custom redaction/review failed");
    if (byName["ssn-validator-and-review"]?.result?.text !== "[ssn_us] / 000-45-6789") throw new Error("SSN validation failed");
    if (byName["card-iban-redact"]?.result?.labels?.join(",") !== "card,iban") throw new Error("card or IBAN validation failed");
    if (byName["source-and-medical"]?.result?.labels?.join(",") !== "medical,source_code") throw new Error("source or medical classification failed");
  }
  console.log("native/WASM parity " + edition + " vectors=" + actual.length + " repeats=32");
} finally { await new Promise(resolve => server.close(resolve)); }
