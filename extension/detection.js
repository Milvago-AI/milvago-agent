import './adapters.js';
import {strictJSON,hostOf} from './model-access.js';
export const BODY_LIMIT=128*1024;
// Ceiling of the DECOMPRESSED body, distinct from the transmitted body's ceiling. Measured on
// claude.ai on 2026-09-14: 21,191 bytes on the wire render 108,884 bytes, of which 100 KB
// are MCP tool definitions rather than prompt. A workstation with a few more connectors would
// cross 128 KiB and silently lose the model column again.
export const INFLATED_LIMIT=1024*1024;
// Providers compress their request body client-side. `TextDecoder` then fails on the
// second byte and the whole observation is lost: this is what emptied Claude's model
// column from the start, even though its network rule was correct.
function compressionOf(u8){
 if(u8.length>=2&&u8[0]===0x1f&&u8[1]===0x8b){return 'gzip';}
 if(u8.length>=2&&u8[0]===0x78&&[0x01,0x9c,0xda,0x5e].includes(u8[1])){return 'deflate';}
 // Brotli has no signature and zstd (28 b5 2f fd) is not supported by
 // DecompressionStream: they fall through to strict decoding, which fails and yields
 // `body:null` with `body_bytes` kept. A visible refusal, never a silent one.
 return null;
}
async function inflate(u8,format){
 if(typeof DecompressionStream!=='function'){return null;}
 const reader=new Blob([u8]).stream().pipeThrough(new DecompressionStream(format)).getReader();
 const chunks=[];let total=0;
 // The ceiling cuts off WHILE reading: a hostile archive decompresses without limit,
 // and checking the size afterward would mean it was already written to memory.
 for(;;){const {done,value}=await reader.read();if(done){break;}
  total+=value.byteLength;if(total>INFLATED_LIMIT){await reader.cancel();return null;}
  chunks.push(value);}
 const out=new Uint8Array(total);let at=0;for(const c of chunks){out.set(c,at);at+=c.byteLength;}
 return out;
}
export function glob(pattern,path){
 if(typeof pattern!=='string'||pattern.length>256||typeof path!=='string'||path.length>4096){return false;}
 const parts=pattern.split('*');let at=0;
 if(!path.startsWith(parts[0])){return false;}at=parts[0].length;
 for(let i=1;i<parts.length;i++){const part=parts[i];const next=path.indexOf(part,at);if(next<0){return false;}at=next+part.length;}
 return pattern.endsWith('*')||at===path.length;
}
export function valuesAt(value,path){
 if(!path){return [];}let values=[value];
 for(const part of path.split('.')){
  const each=part.endsWith('[*]'),key=each?part.slice(0,-3):part;
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(key)||['__proto__','constructor','prototype'].includes(key)){return [];}
  values=values.flatMap(v=>{if(!v||typeof v!=='object'||!Object.hasOwn(v,key)){return [];}if(!each){return [v[key]];}if(Array.isArray(v[key])){return v[key];}return [];}).slice(0,1024);
 }return values;
}
export async function fingerprint(text){const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));return Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');}
// Chrome puts an `application/x-www-form-urlencoded` body — and the text fields of a
// multipart one — in `requestBody.formData`, never in `raw`. This path used to be refused
// outright: anonymous/mobile ChatGPT's send (`POST /unauth-mweb/conversation/updates`,
// measured on 2026-09-15) and Gemini's were therefore unreadable, and no catalogue rule
// could do anything about it. FILE content never appears in `formData` and is
// never read: only text fields are exposed.
export function decodeForm(form){
 if(!form||typeof form!=='object'||Array.isArray(form)){return null;}
 const body={};let total=0,keys=0;
 for(const [key,values] of Object.entries(form)){
  // A key that a catalogue path could not name has no business being exposed:
  // `valuesAt` holds segments to that same shape.
  if(!Array.isArray(values)||!/^[A-Za-z0-9_-]{1,64}$/.test(key)||['__proto__','constructor','prototype'].includes(key)){continue;}
  const strings=values.filter(v=>typeof v==='string');if(!strings.length){continue;}
  for(const value of strings){total+=value.length;}
  if(total>BODY_LIMIT||++keys>256){return null;}
  body[key]=strings.length===1?strings[0]:strings;
 }
 return body;
}
// A form field can carry a whole JSON document: mobile ChatGPT puts its
// attachments (`imageAttachments`) and thread state (`conversationState`) there. The
// rule NAMES these fields. Trying to deserialize every value would be worse than the
// problem it solves: a prompt that happens to be JSON would become an object, and its
// text would silently disappear.
export function unwrapFields(body,fields){
 if(!body||typeof body!=='object'||Array.isArray(body)||!Array.isArray(fields)||!fields.length){return body;}
 const out={...body};
 for(const field of fields.slice(0,4)){
  // `out[field]=…` on `__proto__` would write the object's prototype, not a field:
  // the catalogue is signed, but an engine does not rely on that alone.
  if(typeof field!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(field)||['__proto__','constructor','prototype'].includes(field)){continue;}
  const value=out[field];if(typeof value!=='string'){continue;}
  try{const parsed=strictJSON(value,BODY_LIMIT);if(parsed&&typeof parsed==='object'){out[field]=parsed;}}catch{/* the field stays the string it is */}
 }
 return out;
}
export async function decodeBody(details){
 let bytes=0;const raw=details.requestBody?.raw;
 if(details.requestBody?.error){return {body:null,body_bytes:null};}
 if(details.requestBody?.formData){
  // Chrome renders the decoded fields here, not the transmitted bytes: reporting a size
  // would mean inventing one, which is why `body_bytes` is optional here.
  return {body:decodeForm(details.requestBody.formData),body_bytes:null};
 }
 if(!Array.isArray(raw)){return {body:null,body_bytes:null};}
 for(const part of raw){if(!part.bytes||part.file){return {body:null,body_bytes:null};}bytes+=part.bytes.byteLength;if(bytes>16*1024*1024){return {body:null,body_bytes:null};}}
 if(bytes>BODY_LIMIT){return {body:null,body_bytes:bytes};}
 try{
  const joined=new Uint8Array(bytes);let at=0;for(const part of raw){joined.set(new Uint8Array(part.bytes),at);at+=part.bytes.byteLength;}
  const format=compressionOf(joined);
  if(!format){return {body:strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(joined)),body_bytes:bytes};}
  const gonfle=await inflate(joined,format);
  if(!gonfle){return {body:null,body_bytes:bytes};}
  // Decompressed content goes through `strictJSON`, never `JSON.parse`: the refusal of
  // duplicate keys at any depth must hold on this path too. `body_bytes` keeps the
  // meaning of TRANSMITTED size — changing that meaning would skew the history already
  // collected.
  return {body:strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(gonfle),INFLATED_LIMIT),body_bytes:bytes};
 }catch{return {body:null,body_bytes:bytes};}
}
// One value at a path, or none. A path that yields several conforming candidates is
// ambiguous and reports nothing, on the same principle as two rules matching one route.
// It is what stops a plausible wrong answer: Le Chat states its reasoning by *adding*
// `beta-reasoning` to a `features` array, so an `effort_path` of `features[*]` would
// otherwise report `beta-code-interpreter` — the first conforming string of the list.
// Silent and wrong is worse than empty.
// One path segment of the request URL, when a rule names its index. Bounded like the
// catalogue bounds it, and held to the same shape as an identifier read from a body:
// a segment that is not one reports nothing rather than a plausible wrong answer.
export function segmentOf(url,index){
 if(!Number.isInteger(index)||index<0||index>16){return undefined;}
 const segment=url.pathname.split('/').filter(Boolean)[index];
 return typeof segment==='string'&&/^[A-Za-z0-9_-]{1,200}$/.test(segment)?segment:undefined;
}
export function only(body,path,shape){
 const values=valuesAt(body,path).filter(v=>typeof v==='string'&&shape.test(v));
 return values.length===1?values[0]:undefined;
}
// The rule that describes a request, or none. Method, host and path only: an
// ambiguous match is not settled at random, it observes nothing. Upload routes
// (`kind:"file"`) are excluded — they carry no prompt, and observing them would
// produce a zero-character event.
//
// Synchronous, because the blocking `webRequest` handler is: it is the same
// definition of "which rule describes this request" on both sides, never two.
export function matchRule(catalog,details,url,kind='prompt'){
 // Trailing dot stripped: `claude.ai.` is the same host, and its route must not stop being one.
 const host=hostOf(url);
 const matches=catalog?.providers.flatMap(p=>(p.network||[]).filter(n=>(n.kind||'prompt')===kind&&n.method===details.method&&n.host===host&&glob(n.path,url.pathname)).map(rule=>({provider:p,rule})))||[];
 return matches.length===1?matches[0]:null;
}
// The text a request carries, read without awaiting anything. A compressed body stays
// unreadable here — `DecompressionStream` is asynchronous — and declares itself as such
// rather than passing for an empty body: this is the difference between "nothing to
// mask" and "I could not read it".
function decodeRawSync(parts){
 let bytes=0;
 for(const part of parts){
  if(!part.bytes||part.file){return {readable:false,texts:[]};}
  bytes+=part.bytes.byteLength;
 }
 if(bytes>BODY_LIMIT){return {readable:false,texts:[]};}
 const joined=new Uint8Array(bytes);
 let at=0;
 for(const part of parts){joined.set(new Uint8Array(part.bytes),at);at+=part.bytes.byteLength;}
 if(compressionOf(joined)){return {readable:false,texts:[]};}
 try{return {decoded:strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(joined))};}
 catch{return {readable:false,texts:[]};}
}
function decodeBodySync(raw){
 if(raw?.error){return {readable:false,texts:[]};}
 if(raw?.formData){return {decoded:decodeForm(raw.formData)};}
 if(Array.isArray(raw?.raw)){return decodeRawSync(raw.raw);}
 return {decoded:null};
}
export function bodyTextSync(details,rule){
 const read=decodeBodySync(details.requestBody);
 if(!Object.hasOwn(read,'decoded')){return read;}
 const {decoded}=read;
 if(decoded===null||typeof decoded!=='object'){return {readable:decoded!==null,texts:[],body:decoded};}
 const body=unwrapFields(decoded,rule?.json_fields);
 return {readable:true,texts:rule?textsAt(body,rule):[],body};
}
// What the catalogue can say about a request without awaiting anything: file route,
// readable body, carried text. `model-access.js` decides from this and therefore does not
// import this module — an import cycle in the blocking path would cost dearly at the
// first change in evaluation order.
export function wireFacts(details,catalog,url){
 const file=!!matchRule(catalog,details,url,'file');
 if(file){return {file:true,readable:false,texts:[],body:null};}
 const match=matchRule(catalog,details,url);
 const read=bodyTextSync(details,match?.rule);
 // `route`: the request is a PROMPT route of the catalogue. Under masking, this — and a
 // body shaped like a prompt — is what the decision keeps, and nothing else.
 return {file:false,route:!!match,readable:read.readable,texts:read.texts,body:read.body??null};
}
// The candidate text paths, tried in order, the first one to yield text winning.
// Shared by the observation and by the blocking decision.
function textsAt(body,rule){
 const candidates=Array.isArray(rule.text_paths)&&rule.text_paths.length?rule.text_paths:[rule.text_path];
 for(const candidate of candidates){
  const found=valuesAt(body,candidate).filter(v=>typeof v==='string');
  if(found.length){return found;}
 }
 return [];
}
export async function observeRequest(details,catalog,modelEnabled=false){
 let url;try{url=new URL(details.url);if(url.protocol!=='https:'||url.username||url.password||url.port){return null;}}catch{return null;}
 const match=matchRule(catalog,details,url);
 if(!match){return null;}
 const {provider,rule}=match,{body:decoded,body_bytes}=await decodeBody(details);
 const body=unwrapFields(decoded,rule.json_fields);
 // One route can carry two body shapes: Le Chat names the text `content[*].text` when
 // it opens a thread and `messageInput[*].text` afterwards. Two rules cannot settle
 // it — they match on method, host and path alone, and two matches make the whole
 // observation ambiguous — so a rule may name several candidate paths and the first
 // that yields text wins. It also absorbs a provider renaming a field between two
 // versions of its interface.
 const texts=textsAt(body,rule);
 const text=texts.join('');
 const model=modelEnabled?only(body,rule.model_path,/^[A-Za-z0-9._:/-]{1,200}$/):undefined;
 // The reasoning effort the request asked for. Providers name it differently
 // (`effort`, `thinking_effort`), hence its own path in the rule; the page only ever
 // shows it fused into a translated model label.
 const effort=modelEnabled?only(body,rule.effort_path,/^[a-z0-9_-]{1,40}$/):undefined;
 // The body first, then the request path. claude.ai never names the conversation in
 // its body: the identifier exists only as a path segment of
 // `/api/organizations/<org>/chat_conversations/<uuid>/completion`, so a rule with no
 // way to point at a segment could not observe it at all, and the page URL was the
 // only source left -- which on a provider that changes conversation without reloading
 // is exactly the source that fails.
 const conversation=only(body,rule.conversation_path,/^[A-Za-z0-9_-]{1,200}$/)??segmentOf(url,rule.conversation_url_segment);
 // Attached file names, when the request states them — this is the only path
 // where interception of the file picker does not exist. Several values are
 // legitimate here, as with text: it is not an ambiguity. Never their
 // content, and the policy decides afterward whether they are kept.
 const files=(rule.files_path?valuesAt(body,rule.files_path):[]).filter(name=>typeof name==='string'&&name.length>0&&name.length<=200&&![...name].some(c=>c.codePointAt(0)<32||c.codePointAt(0)===127)).slice(0,20);
 return {provider,characters:texts.length?Array.from(text).length:0,characters_known:!!texts.length,body_bytes,model,effort,conversation_id:conversation,files,fingerprint:texts.length?await fingerprint(text):null};
}
export async function candidateSignals(details,catalog){
 const {body}=await decodeBody(details);if(!body||Array.isArray(body)||typeof body!=='object'){return [];}
 const keys=catalog?.heuristics?.keys||['messages','prompt','model','input'];return keys.filter(k=>Object.hasOwn(body,k)).length>=2?['json_keys']:[];
}
// Content fingerprints exist only in memory. Durable entries contain metadata
// and a stable delivery identity, so a lost receipt can be retried unchanged.
export class Fusion {
 constructor(emit,clock=()=>Date.now(),persist=async()=>{}){this.emit=emit;this.clock=clock;this.persist=persist;this.pending=[];this.inflight=new Set();this.serial=Promise.resolve();}
 run(fn){const result=this.serial.then(fn);this.serial=result.catch(()=>{});return result;}
 async commit(next){await this.persist(next.map(({digest,...entry})=>entry));this.pending=next;}
 restore(entries){
  if(!Array.isArray(entries)||entries.length>128||new TextEncoder().encode(JSON.stringify(entries)).length>1024*1024){throw new Error('Invalid pending detection metadata');}
  for(const p of entries){if(!p||typeof p.id!=='string'||!(/^[0-9a-f-]{36}$/i).test(p.id)||typeof p.identity!=='string'||p.identity.length>512||!Number.isFinite(p.at)||!['dom','network','both','presence'].includes(p.source)||typeof p.attempted!=='boolean'||(p.submission!==undefined&&typeof p.submission!=='boolean')||!p.event||Object.hasOwn(p,'digest')){throw new Error('Invalid pending detection entry');}}
  if(new Set(entries.map(p=>p.id)).size!==entries.length){throw new Error('Duplicate pending delivery identity');}
  this.pending=entries.map(p=>({...p,digest:null,at:Math.min(p.at,this.clock())}));
 }
 // `observed` is what the request itself said about this exchange, carried only as
 // far as the delivery: a send made durable before it left cannot hold the identifier
 // of the conversation it was about to create. It is never stored -- only the pending
 // entry is -- and it never replaces the event.
 async deliver(p,observed){
  const retry=p.attempted;
  if(!p.attempted){const changed={...p,attempted:true};await this.commit(this.pending.map(row=>row===p?changed:row));p=changed;}
  await this.emit({...p.event,detector:p.source},p.id,retry,p.submission===true,p.authority,observed);
  await this.commit(this.pending.filter(row=>row!==p));
 }
 async mergeMatch(p,event,source){
  // Once delivery was attempted its payload cannot change: Update may already
  // hold it and only its acknowledgement may have been lost.
  if(!p.attempted){const network=source==='network'?event:p.event,dom=source==='dom'?event:p.event;const merged={...p,event:{...dom,...network,correlation_id:dom.correlation_id||network.correlation_id},source:'both'};await this.commit(this.pending.map(row=>row===p?merged:row));p=merged;}
  await this.deliver(p);
 }
 async deliverExisting(existing,event,identity,source,immediate,authority){
  if(existing.identity!==identity||existing.authority!==authority||existing.source!==source||JSON.stringify(existing.event)!==JSON.stringify(event)){throw new Error('Capture delivery identity collision');}
  if(immediate){await this.deliver(existing);}
  return existing.id;
 }
 async addPending({event,identity,digest,source,immediate,authority,deliveryId,now}){
  if(this.pending.length>=128){throw new Error('Pending detection queue full');}
  const entry={id:deliveryId||crypto.randomUUID(),event:structuredClone(event),authority,identity,digest,source,at:now,attempted:false};
  await this.commit([...this.pending,entry]);
  if(immediate){await this.deliver(entry);}
  return entry.id;
 }
 add(event,identity,digest,source,immediate,authority,deliveryId){
  if(immediate===undefined){immediate=false;}
  if(authority===undefined){authority=null;}
  return this.run(async()=>{
   if(deliveryId!==undefined&&!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-58][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deliveryId)){throw new Error('Invalid capture delivery identity');}
   const existing=deliveryId&&this.pending.find(p=>p.id===deliveryId);
   if(existing){return this.deliverExisting(existing,event,identity,source,immediate,authority);}
   const now=this.clock();
   const matches=this.pending.filter(p=>p.identity===identity&&p.authority===authority&&p.digest&&p.digest===digest&&p.source!==source&&p.source!=='both'&&now>=p.at&&now-p.at<=3000);
   if(matches.length===1){await this.mergeMatch(matches[0],event,source);return;}
   return this.addPending({event,identity,digest,source,immediate,authority,deliveryId,now});
  });
 }
 prepare(event,identity,authority=null){return this.run(async()=>{
  if(this.pending.length>=128){throw new Error('Pending detection queue full');}
  const entry={id:crypto.randomUUID(),event:structuredClone(event),authority,identity,digest:null,source:'dom',at:this.clock(),attempted:true,submission:true};
  await this.commit([...this.pending,entry]);this.inflight.add(entry.id);return entry.id;
 });}
 acknowledge(id){return this.run(async()=>{await this.commit(this.pending.filter(p=>p.id!==id));this.inflight.delete(id);});}
 release(id){this.inflight.delete(id);}
 has(identity,source){return this.pending.some(p=>p.identity===identity&&p.source===source);}
 retain(keep){return this.run(async()=>{await this.commit(this.pending.filter(entry=>keep(entry)));});}
 resume(event,identity,id,authority=null){return this.run(async()=>{
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-58][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)){throw new Error('Invalid delivery receipt');}
  let entry=this.pending.find(p=>p.id===id);if(entry&&entry.authority!==authority){throw new Error('Pending receipt authority changed');}
  if(!entry){if(this.pending.length>=128){throw new Error('Pending detection queue full');}entry={id,event:structuredClone(event),authority,identity,digest:null,source:'network',at:this.clock(),attempted:true};await this.commit([...this.pending,entry]);}
  if(this.inflight.has(id)){throw new Error('Submission still in flight');}
  await this.deliver(entry,event);
 });}
 flush(){return this.run(async()=>{const now=this.clock();for(const p of this.pending){if(!this.inflight.has(p.id)&&(p.attempted||now-p.at>=3000||now<p.at)){await this.deliver(p);}}});}
 clear(){return this.run(async()=>{await this.commit([]);this.inflight.clear();});}
}
