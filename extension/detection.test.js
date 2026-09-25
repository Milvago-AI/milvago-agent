import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {observeRequest,decodeBody,valuesAt,glob,Fusion,candidateSignals} from './detection.js';
const provider={id:'fixture',label:'Fixture',domains:['fixture.test'],aliases:[],conversation_path:'/c/*',conversation_segment:1,dom:{editor:'',send:'',response:''},qualified_at:'2026-09-11T00:00:00Z',network:[{method:'POST',host:'fixture.test',path:'/complete',text_path:'input',model_path:'model',conversation_path:'session'}]};
const catalog={providers:[provider],native_tools:[],heuristics:{keys:['prompt','model','input','messages'],mime_types:['text/event-stream']}};
const request=body=>({requestId:'req',tabId:1,documentId:'document',method:'POST',url:'https://fixture.test/complete',requestBody:{raw:[{bytes:new TextEncoder().encode(body).buffer}]}});
// Providers compress their request body client-side. Measured on claude.ai on
// 2026-09-14: the completion arrives gzip-encoded (`1f 8b`), 21,191 bytes on the wire for
// 108,884 decompressed. `decodeBody` used to fail at the second byte and the whole
// observation was lost — empty model column, plus a second network event with no
// fingerprint that could no longer merge with the DOM event.
const compresse=async(texte,format='gzip')=>{
 const flux=new Blob([new TextEncoder().encode(texte)]).stream().pipeThrough(new CompressionStream(format));
 return new Uint8Array(await new Response(flux).arrayBuffer()).buffer;
};
const requeteBrute=octets=>({requestId:'req',tabId:1,documentId:'document',method:'POST',url:'https://fixture.test/complete',requestBody:{raw:[{bytes:octets}]}});

test('a gzip request body is decompressed, and its model and effort are read',async()=>{
 const corps='{"input":"synthetic","model":"fixture-model","effort":"high","session":"session-9"}';
 const octets=await compresse(corps);
 const r=await observeRequest(requeteBrute(octets),catalog,true);
 assert.equal(r.model,'fixture-model');assert.equal(r.characters,9);assert.equal(r.conversation_id,'session-9');
 // `body_bytes` keeps the meaning of TRANSMITTED size, the bytes actually sent —
 // not the readable content size. Changing that meaning would skew history already collected.
 assert.equal(r.body_bytes,octets.byteLength);
 assert.equal((await decodeBody(requeteBrute(await compresse(corps,'deflate')))).body.model,'fixture-model');
});

test('a decompression bomb is refused by the output ceiling, not by the transmitted size',async()=>{
 // A few kilobytes on the wire, well past the ceiling once expanded: the refusal
 // must come from reading the stream, not from a check after the fact — otherwise memory
 // is already written by the time it's noticed.
 const bombe=await compresse('{"input":"'+'a'.repeat(3*1024*1024)+'"}');
 assert.ok(bombe.byteLength<128*1024,'la bombe doit passer le plafond du corps transmis');
 const r=await decodeBody(requeteBrute(bombe));
 assert.equal(r.body,null);assert.equal(r.body_bytes,bombe.byteLength);
});

test('an unsupported compression and a duplicate key inside a compressed body are both refused',async()=>{
 // zstd: recognizable signature, not supported by DecompressionStream. The refusal
 // must be visible — body null, body_bytes kept — never a half-read body.
 const zstd=new Uint8Array([0x28,0xb5,0x2f,0xfd,0x00,0x01,0x02,0x03]).buffer;
 const z=await decodeBody(requeteBrute(zstd));assert.equal(z.body,null);assert.equal(z.body_bytes,8);
 // Decompressed content goes through strictJSON, not JSON.parse: the rejection of
 // duplicate keys at any depth also applies to this path.
 const d=await decodeBody(requeteBrute(await compresse('{"input":"a","input":"b"}')));
 assert.equal(d.body,null);assert.ok(d.body_bytes>0);
});

test('qualified network works with empty DOM, measures unicode characters, withholds Community model and text',async()=>{
 const r=await observeRequest(request('{"input":"a😀","model":"fixture-model","session":"session-1"}'),catalog,false);
 assert.equal(r.characters,2);assert.equal(r.characters_known,true);assert.equal(r.model,undefined);assert.equal(r.conversation_id,'session-1');assert.match(r.fingerprint,/^[0-9a-f]{64}$/);assert.ok(!JSON.stringify(r).includes('a😀'));
 assert.equal((await observeRequest(request('{"input":"a","model":"fixture-model"}'),catalog,true)).model,'fixture-model');
});
test('unknown measurements retain bytes independently, oversized and duplicate JSON are not parsed',async()=>{
 const bad=await observeRequest(request('{"input":"a","input":"b"}'),catalog);assert.equal(bad.characters_known,false);assert.equal(bad.characters,0);assert.ok(bad.body_bytes>0);
 const large=await decodeBody(request('x'.repeat(131073)));assert.equal(large.body,null);assert.equal(large.body_bytes,131073);
 assert.deepEqual(valuesAt({messages:[{content:'a'},{content:'b'}]},'messages[*].content'),['a','b']);assert.deepEqual(valuesAt({},'__proto__.secret'),[]);
});
test('declarative rules cannot execute regex or choose unqualified URL',async()=>{
 assert.equal(glob('/v1/*','/v1/messages'),true);assert.equal(glob('/v1/*','/v2/messages'),false);
 assert.equal(await observeRequest({...request('{}'),url:'https://fixture.test/other'},catalog),null);
 assert.equal(await observeRequest({...request('{}'),url:'https://fixture.test:8443/complete'},catalog),null);
});
test('fusion requires digest and document, handles two close prompts and keeps unmatched requests',async()=>{
 let time=0;const events=[];const f=new Fusion(e=>events.push(e),()=>time);
 await f.add({characters:1},'tab|doc|fixture','aaa','network');await f.add({characters:2},'tab|doc|fixture','bbb','network');
 await f.add({characters:1,correlation_id:'one'},'tab|doc|fixture','aaa','dom');await f.add({characters:2,correlation_id:'two'},'tab|doc|fixture','bbb','dom');
 assert.equal(events.length,2);assert.deepEqual(events.map(e=>e.detector),['both','both']);assert.deepEqual(events.map(e=>e.correlation_id),['one','two']);
 await f.add({characters:3},'tab|other|fixture','ccc','dom');await f.add({characters:3},'tab|doc|fixture','ccc','network');time=3001;await f.flush();assert.equal(events.length,4);
});
test('candidate signal is shape only and factory matches cover every factory domain',async()=>{
 assert.deepEqual(await candidateSignals(request('{"input":"synthetic","model":"fixture"}'),catalog),['json_keys']);assert.deepEqual(await candidateSignals(request('{"input":"synthetic"}'),catalog),[]);
 const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url)));const matches=manifest.content_scripts.flatMap(s=>s.matches);
 const factory=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url)));const notebook=factory.providers.find(p=>p.id==='notebooklm');
 // The hostname Google actually serves is `notebook.google.com`. It must be in
 // `domains`, not `aliases`: `enrichDetectionPolicy` only copies `Domains` into
 // the signed policy, and `eventForPolicy` compares the tab's REAL hostname. An
 // alias left in `aliases` silently drops every DOM event from that site.
 assert.deepEqual(notebook.domains,['notebook.google.com','notebooklm.google.com']);assert.deepEqual(notebook.aliases,[]);assert.ok(matches.includes('https://notebook.google.com/*'));
 for(const provider of factory.providers){for(const domain of [...provider.domains,...provider.aliases]){assert.ok(matches.includes('https://'+domain+'/*'));}}
 globalThis.MilvagoAdapters.applyCatalog(null);for(const a of globalThis.MilvagoAdapters.adapters){assert.ok(matches.includes('https://'+a.domain+'/*'));}
 for(const domain of Object.keys(globalThis.MilvagoAdapters.aliases)){assert.ok(matches.includes('https://'+domain+'/*'));}
});
test('catalog installs declarative adapters then expiration fallback restores factory',()=>{
 const A=globalThis.MilvagoAdapters;A.applyCatalog(catalog);assert.equal(A.resolve('https://fixture.test/c/abcdefgh').id,'fixture');assert.equal(A.context('https://fixture.test/c/abcdefgh?private=x').conversation_id,'abcdefgh');
 assert.equal(A.resolve('https://fixture.test.attacker.test/'),null);A.applyCatalog(null);assert.equal(A.resolve('https://fixture.test/'),null);assert.equal(A.resolve('https://chatgpt.com/').id,'chatgpt');
});

test('Claude completion scalar fixture qualifies only the declared route, not conversation history',async()=>{
 const factory=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url)));
 const req={...request('{"prompt":"synthetic 😀","model":"fixture-model","context":[{"content":"earlier"}]}'),url:'https://claude.ai/api/organizations/fixture-org/chat_conversations/fixture-chat/completion'};
 const hit=await observeRequest(req,factory,true);assert.equal(hit.characters,11);assert.equal(hit.model,'fixture-model');
 assert.equal(await observeRequest({...req,url:'https://claude.ai/api/organizations/fixture-org/chat_conversations/fixture-chat'},factory,true),null);
 // Providers carrying a network rule, named rather than counted: a count
 // alone doesn't say which one was lost. Measured on their real routes on 2026-09-14;
 // the other seven don't have one yet, and an empty field there is a fact, not an oversight.
 assert.deepEqual(factory.providers.filter(p=>p.network.length).map(p=>p.id).sort(),['chatgpt','claude','perplexity']);
 // Perplexity has no DOM path at all: its network rule is its ONLY observation. If it
 // disappears, the provider goes completely silent without any other test
 // noticing — hence these named assertions.
 const px=factory.providers.find(p=>p.id==='perplexity');
 assert.deepEqual([px.dom.editor,px.dom.send,px.dom.response],['','','']);
 assert.equal(px.network[0].model_path,'params.model_preference');
 assert.deepEqual(px.network[0].text_paths,['query_str','params.dsl_query']);
 const gpt=factory.providers.find(p=>p.id==='chatgpt').network[0];
 assert.equal(gpt.model_path,'model');assert.equal(gpt.effort_path,'thinking_effort');
 assert.deepEqual(gpt.text_paths,['messages[*].content.parts[*]']);
 // `effort` and `thinking_mode` are TWO distinct fields, measured on 2026-09-15 on two
 // real models: Opus sends `effort:"high"` when High effort is selected, AND
 // `thinking_mode:"auto"` alongside it; Haiku sends no `effort` at all — that model
 // doesn't expose this setting — only `thinking_mode:"extended"`. Concluding from the
 // Haiku measurement alone that effort lived in `thinking_mode` surfaced "auto" where
 // the person had actually chosen "High": a plausible and wrong value, worse than an
 // empty column. `effort_path` therefore targets the field that actually carries the
 // setting.
 const claude=factory.providers.find(p=>p.id==='claude').network[0];
 assert.equal(claude.effort_path,'effort');
 // Claude NEVER names the conversation in its body: the identifier only exists
 // as a path segment, hence `conversation_url_segment`, whose index is measured.
 assert.equal(claude.conversation_path,'');
 assert.equal(claude.conversation_url_segment,4);
 const url='https://claude.ai/api/organizations/fixture-org/chat_conversations/fixture-chat/completion';
 const both=await observeRequest({...request('{"prompt":"x","model":"fixture-model","effort":"high","thinking_mode":"auto"}'),url},factory,true);
 assert.equal(both.conversation_id,'fixture-chat');
 assert.equal(both.effort,'high');
});

// Measured on the real request on 2026-09-15: Claude's conversation identifier
// only exists in the path, `/api/organizations/<org>/chat_conversations/<uuid>/completion`,
// i.e. the segment at index 4. Without this reading, the only remaining source is the
// page URL, the very one that fails when a provider switches conversation without
// reloading. The body still takes priority: a segment never overrides a value read
// where the rule declared it.
test('a rule may read the conversation identifier from the request path, the body first',async()=>{
 const factory=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url)));
 const claude=factory.providers.find(p=>p.id==='claude');
 const url='https://claude.ai/api/organizations/fixture-org/chat_conversations/fixture-chat/completion';
 const hit=await observeRequest({...request('{"prompt":"synthetic","model":"fixture-model"}'),url},factory,true);
 assert.equal(hit.conversation_id,'fixture-chat');

 // A segment that names nothing usable reports nothing, rather than a plausible wrong
 // answer: the same rule as an ambiguous body path.
 claude.network[0].conversation_url_segment=5;
 assert.equal((await observeRequest({...request('{"prompt":"synthetic"}'),url},factory,true)).conversation_id,'completion');
 claude.network[0].conversation_url_segment=9;
 assert.equal((await observeRequest({...request('{"prompt":"synthetic"}'),url},factory,true)).conversation_id,undefined);

 // Declared in the body, the body wins: a rule that names both is not ambiguous.
 claude.network[0].conversation_path='conversation_id';
 claude.network[0].conversation_url_segment=4;
 assert.equal((await observeRequest({...request('{"prompt":"x","conversation_id":"from-body"}'),url},factory,true)).conversation_id,'from-body');
});
