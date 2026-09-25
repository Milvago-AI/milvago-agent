const decoder = new TextDecoder();
const encoder = new TextEncoder();
export async function loadBrowserEngine(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error("browser engine unavailable");
  const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
  const api = instance.exports;
  for (const name of ["memory", "milvago_engine_alloc", "milvago_engine_inspect_json", "milvago_engine_free"]) {
    if (!(name in api)) throw new Error("browser engine ABI unavailable");
  }
  return { inspectJson(input) {
    const bytes = encoder.encode(input);
    const pointer = api.milvago_engine_alloc(bytes.length);
    new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes);
    const packed = api.milvago_engine_inspect_json(pointer, bytes.length);
    const outputPointer = Number(packed & 0xffffffffn);
    const outputLength = Number(packed >> 32n);
    try { return decoder.decode(new Uint8Array(api.memory.buffer, outputPointer, outputLength)); }
    finally { api.milvago_engine_free(outputPointer, outputLength); }
  }};
}
