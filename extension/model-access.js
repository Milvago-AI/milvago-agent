import './adapters.js';
// The per-model decision lives in model-rules.js so the Community package can swap
// it for a stub. Everything below is shared by both editions and must stay here.
import { modelDecision, requestModel, ruleFor } from './model-rules.js';
export {modelRulesValid} from './model-rules.js'; export { modelDecision, requestModel, ruleFor };
export const apiHosts={'api.openai.com':'chatgpt','api.anthropic.com':'claude'};
// The hostname without its trailing dot: `api.anthropic.com.` reaches the same server, and an
// exact comparison let it slip past every guard.
export function hostOf(u){const name=u.hostname;let end=name.length;while(end>0&&name[end-1]==='.'){end--;}return name.slice(0,end);}
// Reject duplicate keys including escaped spellings, at every depth, before JSON.parse.
// Default `limit` unchanged. Only the asynchronous observation in `detection.js` raises it,
// for a decompressed body whose size no longer matches the one on the wire. The Enterprise
// control in `model-rules.js` decides, for its part, inside a BLOCKING webRequest handler:
// it must stay synchronous and tight, and never calls with another value.
export function strictJSON(text,limit=131072){
 if(text.length>limit){throw new Error('body too large');}
 let at=0,depth=0;
 function ws(){while(/[ \t\r\n]/.test(text[at]||'\0')){at++;}}
 function string(){const start=at++;while(at<text.length){const c=text[at++];if(c==='"'){return JSON.parse(text.slice(start,at));}if(c==='\\'){at++;}}throw new Error('string');}
 function member(keys){
  if(text[at]!=='"'){throw new Error('key');}
  const key=string();
  if(keys.has(key)){throw new Error('duplicate');}
  keys.add(key);
  ws();
  if(text[at++]!==':'){throw new Error('colon');}
  value();
 }
 function object(){
  at++;ws();
  const keys=new Set();
  if(text[at]!=='}'){
   for(;;){ws();member(keys);ws();if(text[at]!==','){break;}at++;}
  }
  if(text[at++]!=='}'){throw new Error('object');}
 }
 function array(){
  at++;ws();
  if(text[at]!==']'){
   for(;;){value();ws();if(text[at]!==','){break;}at++;}
  }
  if(text[at++]!==']'){throw new Error('array');}
 }
 function primitive(){
  const start=at;
  while(at<text.length&&!/[,}\]\s]/.test(text[at])){at++;}
  if(start===at){throw new Error('value');}
 }
 function value(){
  ws();
  if(++depth>40){throw new Error('depth');}
  const c=text[at];
  if(c==='{'){object();}
  else if(c==='['){array();}
  else if(c==='"'){string();}
  else{primitive();}
  depth--;
 }
 value();ws();if(at!==text.length){throw new Error('trailing');}
 return JSON.parse(text);
}
export function requestBodyJSON(details){ try{
  let length=0;for(const part of details.requestBody.raw){if(!part.bytes||part.file){return null;}length+=part.bytes.byteLength;if(length>131072){return null;}}
  const bytes=new Uint8Array(length);let offset=0;for(const part of details.requestBody.raw){bytes.set(new Uint8Array(part.bytes),offset);offset+=part.bytes.byteLength;}
  return strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }catch{return null;}
}
function urlOf(value){try{const u=new URL(value);return ['https:','wss:'].includes(u.protocol)&&!u.username&&!u.password&&!u.port?u:null;}catch{return null;}}
// `URL` drops a default port (`:443`) and an empty one: a destination is read as written, so a
// redirect is refused for any port, as the server and the engine refuse it.
function writtenPort(value){return typeof value!=='string'||/^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#\\@]*@)?(?:\[[^\]]*\]|[^/?#\\:[]*):/i.test(value);}
export function networkPlatform(value){let u;try{u=new URL(value);if(!['https:','http:','wss:','ws:'].includes(u.protocol)){return null;}}catch{return null;}if(apiHosts[hostOf(u)]){return globalThis.MilvagoAdapters.adapters.find(a=>a.id===apiHosts[hostOf(u)]);}u.protocol='https:';u.username='';u.password='';u.port='';return globalThis.MilvagoAdapters.resolve(u.href);}
export function contentControl(policy){const protection=policy?.config?.protection;return !!(policy?.config?.dlp_control?.enabled||policy?.config?.privacy?.enabled||protection?.block_uploads||(protection?.keywords?.length&&['exact','unicode','fuzzy'].some(k=>protection[k]==='block')));}
// The "direct API" (`api.openai.com`, `api.anthropic.com`) has no composer to inspect.
// Under masking it stays sealed except for a bodyless read; under file-upload blocking
// alone, only a `file` route from the catalog seals (product decision of 2026-09-16), and
// API hosts carry none. The "full text body" qualification that allowed an API request
// under file-upload blocking therefore disappeared along with the rule it served.
// What a request can carry, under content control. Masking used to seal ALL of the
// provider's traffic, document included: the site would no longer open, no content
// script was there to explain it, and the request rewritten by inspection was cancelled
// like the others — masking therefore never actually masked. Measured on 2026-09-15.
//
// The guard is not lifted, it is moved to where the data actually flows:
//  - a `GET` with no parameters, to the root or from the provider itself, passes,
//    with `Referer` stripped by `background.js` (a path or query carrying data is
//    still refused: `/CONFIDENTIAL`, `?text=…`);
//  - anything carrying a prompt — a catalog route, or a body shaped like a prompt —
//    only goes out if its text is exactly what the agent just approved;
//  - a body this synchronous path cannot read only goes out within its tab's
//    approval window;
//  - the rest of the provider's traffic passes.
// Risk accepted and recorded: a prompt-carrying route unknown to the catalog whose
// body does not look like a prompt would get through.
export function promptShaped(body,keys){
 if(!body||Array.isArray(body)||typeof body!=='object'){return false;}
 const names=keys?.length?keys:['messages','prompt','model','input'];
 return names.filter(k=>Object.hasOwn(body,k)).length>=2;
}
function masks(policy){
 const protection=policy?.config?.protection,privacy=policy?.config?.privacy;
 return !!policy?.config?.dlp_control?.enabled||!!privacy?.enabled||!!(protection?.keywords?.length&&['exact','unicode','fuzzy'].some(k=>protection[k]==='block'));
}
// The provider "at home": its domain or an alias — what `networkPlatform` already
// recognizes —, one of its SUBDOMAINS, or an asset host the catalog names for it.
// Measured on 2026-09-16: `resolve()`'s comparison is on the EXACT hostname, so
// `www.claude.ai`, `cdn.claude.ai` and a provider's CDN were treated as
// exfiltration targets and sealed — the page could not render fully. A
// subdomain shares the registrable domain and the operator; a named host was measured
// on the site. Any OTHER host remains third-party: that is where data would leave, and
// that door does not open. The same URL checks as `urlOf` apply, so that
// a subdomain on a port or carrying credentials does not pass.
// `networkPlatform` answers "which provider IS this host"; this one answers "which
// provider does this host BELONG TO". The two questions are distinct, and conflating them
// cost twice: a page cannot render if something it needs belongs to it without
// carrying its name. Exported because `background.js`'s startup guard must ask the
// same question — forgetting it there used to cancel the provider's assets during the
// whole worker wake-up window, i.e. on every page load (measured on 2026-09-16).
export function ownedPlatform(value){
 const direct=networkPlatform(value);
 if(direct){return direct;}
 let u;try{u=new URL(value);}catch{return null;}
 if(!['https:','wss:'].includes(u.protocol)||u.username||u.password||u.port){return null;}
 const host=hostOf(u);
 return globalThis.MilvagoAdapters.adapters.find(a=>host.endsWith('.'+a.domain)||(a.assets||[]).includes(host))||null;
}
function providerOwned(value,adapter){return ownedPlatform(value)?.id===adapter.id;}
function providerRead(details,adapter){
 if(!['GET','HEAD','OPTIONS'].includes(details.method)||details.requestBody){return false;}
 const navigation=['main_frame','sub_frame'].includes(details.type);
 const initiator=details.initiator||details.originUrl||details.documentUrl;
 return providerOwned(details.url,adapter)&&(navigation||providerOwned(initiator||'',adapter));
}
// SHA-256, synchronous: the blocking handler compares an approval while the request waits, and
// `crypto.subtle` only answers later. The worker keeps a fingerprint of each approved text, never
// the text itself, so what it persists across a restart reveals nothing of the paste.
const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha256(input){
 const ror=(x,n)=>(x>>>n)|(x<<(32-n)),length=input.length,size=((length+9+63)>>6)<<6,data=new Uint8Array(size);
 data.set(input);data[length]=0x80;const view=new DataView(data.buffer);view.setUint32(size-8,Math.floor(length/0x20000000));view.setUint32(size-4,(length*8)>>>0);
 const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],w=new Uint32Array(64);
 for(let at=0;at<size;at+=64){
  for(let i=0;i<16;i++){w[i]=view.getUint32(at+i*4);}
  for(let i=16;i<64;i++){const a=w[i-15],b=w[i-2];w[i]=(w[i-16]+(ror(a,7)^ror(a,18)^(a>>>3))+w[i-7]+(ror(b,17)^ror(b,19)^(b>>>10)))>>>0;}
  let [a,b,c,d,e,f,g,k]=h;
  for(let i=0;i<64;i++){const t1=(k+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+K[i]+w[i])>>>0,t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c)))>>>0;k=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;}
  [a,b,c,d,e,f,g,k].forEach((v,i)=>{h[i]=(h[i]+v)>>>0;});
 }
 return h.map(v=>v.toString(16).padStart(8,'0')).join('');
}
// The fingerprint an approval is compared on: the text under the composer's layout tolerance
// (line breaks, non-breaking spaces, surrounding blanks), or null for a text reduced to blanks.
export function textDigest(text){const laid=globalThis.MilvagoAdapters.layout(text);return laid===''?null:sha256(new TextEncoder().encode(laid));}
// A picked file is approved on the fingerprint of its name: the name itself stays in the page.
export function exactTextDigest(text){return sha256(new TextEncoder().encode(text));}
export function nameDigest(name){return sha256(new TextEncoder().encode(name));}
export function bytesDigest(bytes){return sha256(bytes);}
const DIGEST=/^[0-9a-f]{64}$/;
// A send approval also covers the line-aligned prefixes and suffixes of the inspected text, a few lines
// deep (`parts`): a provider may send the draft typed beside a pasted chip on its own, while the editor
// reads the chip's preview line with it (real campaign 0.7.4). A part of a text inspected whole, cut at a line
// break, carries nothing the inspection did not see.
export const PART_LINES=16;
// How far into a chip its preview is looked for. The editor measured on 2026-10-17 shows the first 100 characters of
// the chip trimmed, each run of blanks as one space (its bundle: `trim().replace(/\s+/g,' ').slice(0,100)`).
const PREVIEW_MAX=256;
export function lineParts(text){
 const lines=globalThis.MilvagoAdapters.layout(text).split('\n'),parts=new Set();
 for(let i=1;i<Math.min(lines.length,PART_LINES+1);i++){parts.add(textDigest(lines.slice(i).join('\n')));parts.add(textDigest(lines.slice(0,-i).join('\n')));}
 parts.delete(null);return [...parts];
}
const partsOf=a=>Array.isArray(a.parts)?a.parts.filter(p=>typeof p==='string'&&DIGEST.test(p)).slice(0,2*PART_LINES):[];
// A tab may hold several approvals: the draft of its last send (`send`, the default), the pastes the
// agent masked and the person confirmed (`paste`), and the text files the person picked (`file`, by
// the fingerprint of their name, and their size). Each serves once. An approval carries its text, or the fingerprint and UTF-8 size
// the worker keeps in its place.
function approvalList(approval){
 return (Array.isArray(approval)?approval:[approval]).flatMap(a=>{
  if(!a||typeof a!=='object'){return [];}
  const kind=a.kind||'send';
  if(kind==='file'){return typeof a.name==='string'&&DIGEST.test(a.name)&&Number.isSafeInteger(a.size)?[{ref:a,kind,name:a.name,size:a.size}]:[];}
  if(!['send','paste'].includes(kind)){return [];}
  if(typeof a.text==='string'){return [{ref:a,kind,exact:exactTextDigest(a.text),digest:textDigest(a.text),bytes:new TextEncoder().encode(a.text).length,parts:kind==='send'?lineParts(a.text):[]}];}
  return (a.digest===null||DIGEST.test(a.digest))&&Number.isSafeInteger(a.bytes)?[{ref:a,kind,exact:DIGEST.test(a.exact||'')?a.exact:null,digest:a.digest,bytes:a.bytes,parts:kind==='send'?partsOf(a):[]}]:[];
 });
}
// A body the guard cannot read rides only on the send just approved: a paste approval lives far
// longer, and must not open that window for its whole life; a file approval names a file, not a send.
// An empty draft's approval carries no text the body could be: it opens nothing (an empty send held
// after a paste or a picked file, then a forged unreadable body).
function unreadableContentDecision(wire,approvals,strict=false){
 if(!wire?.route){return {seal:false};}
 if(strict){return {seal:true};}
 const send=approvals.find(a=>a.kind==='send'&&(a.digest||a.parts?.length));
 return send?{allow:true,approved:true,consumed:[send.ref]}:{seal:true};
}
// Every text path the body fills is covered by the approval of its kind. The draft's path is the
// send just approved (`send`), as one text or, on a list path such as `content[*].text`, as one of
// its elements beside chips a long paste became, each a confirmed paste. An attachment path
// (`attachment_paths`: claude.ai's pasted block) holds pastes only. A paste approval lives far
// longer than a send's: it must never stand for a draft.
// A picked text file a provider sends inline at an attachment path (claude.ai puts a `.txt` beside its
// name and size, real campaign 0.7.6) is covered by that file's approval: one of the names written beside
// it, and its UTF-8 size (a byte-order mark the provider dropped counted). Its content is no more read
// than a file uploaded on its own.
function covering(groups,approvals,strict=false){
 // Contextual NOT/XOR rules are not monotone: neither a fragment nor a
 // whitespace-normalized or independently approved composition is proof.
 if(strict){
  if(groups.length!==1||groups[0].attachment)return null;
  const text=groups[0].join('');if(!text)return null;
  const digest=exactTextDigest(text),hit=approvals.find(a=>a.kind==='send'&&a.exact===digest);
  return hit?[hit.ref]:null;
 }

 const used=new Set(),known=approvals.filter(a=>a.kind!=='file'&&(a.digest||a.parts?.length));
 const take=(value,kind)=>{const digest=textDigest(value),hit=digest&&known.find(a=>a.kind===kind&&(a.digest===digest||a.parts?.includes(digest)));if(hit){used.add(hit.ref);}return !!hit;};
 const picked=(value,names)=>{const bytes=new TextEncoder().encode(value).length,named=new Set((names||[]).map(nameDigest)),hit=approvals.find(a=>a.kind==='file'&&!used.has(a.ref)&&named.has(a.name)&&(a.size===bytes||a.size===bytes+3));if(hit){used.add(hit.ref);}return !!hit;};
 const blank=value=>globalThis.MilvagoAdapters.layout(value)==='';
 const filled=group=>group.filter(v=>!blank(v));
 // A send whose draft held nothing but the chips: empty, or only their preview (the start of each chip, as the
 // editor shows it before the draft); the page then sends the chips alone (real campaign 0.7.11).
 const chipsOnly=chips=>{
  const sends=approvals.filter(a=>a.kind==='send'&&!used.has(a.ref)),wanted=new Set(sends.map(a=>a.digest));
  let hit=sends.find(a=>a.digest===null&&!a.parts?.length);
  for(let length=1;!hit&&length<=PREVIEW_MAX;length++){const digest=textDigest(chips.map(v=>v.trim().replaceAll(/\s+/g,' ').slice(0,length)).join('\n'));if(digest&&wanted.has(digest)){hit=sends.find(a=>a.digest===digest);}}
  if(hit){used.add(hit.ref);}return !!hit;
 };
 const draft=group=>{
  if(take(group.join(''),'send')){return true;}
  let sent=false;const chips=[];
  for(const v of filled(group)){if(take(v,'send')){sent=true;}else if(take(v,'paste')){chips.push(v);}else{return false;}}
  return sent||chips.length>0&&chipsOnly(chips);
 };
 return groups.every(group=>group.attachment?filled(group).length>0&&filled(group).every(v=>take(v,'paste')||picked(v,group.names)):draft(group))?[...used]:null;
}
// A text upload at paste time is one the page made of a long paste: plain text under a `.txt` name,
// as measured on the paste uploads. Only those are compared to a paste on their declared size; any
// other text file leaves only as the file the person picked, on its name and size.
const PASTE_NAME=/\.txt$/i,PASTE_TYPE=/^text\/plain(?:\s*;.*)?$/i;
function pasteShaped(upload){return PASTE_NAME.test(upload.name||'')&&(!upload.type||PASTE_TYPE.test(upload.type));}
// A text file leaves only as a paste the agent approved (its content when the body carries it,
// otherwise its declared byte size) or as a file the person picked. A text file the guard can say
// nothing about is sealed; any other file keeps the file behaviour.
function pasteDecision(wire,approvals,masking){
 if(!masking){return {seal:false};}
 if(!wire.readable){return {seal:true};}
 const consumed=[];
 const free=a=>!consumed.includes(a.ref);
 for(const upload of wire.uploads.filter(u=>u.text)){
  let hit;
  if(typeof upload.content==='string'){const digest=textDigest(upload.content);hit=digest&&approvals.find(a=>a.kind==='paste'&&free(a)&&a.digest===digest);}
  else if(Number.isSafeInteger(upload.size)){
   const named=typeof upload.name==='string'?nameDigest(upload.name):null;
   hit=approvals.find(a=>a.kind==='file'&&free(a)&&a.name===named&&a.size===upload.size)||(pasteShaped(upload)&&approvals.find(a=>a.kind==='paste'&&free(a)&&a.bytes===upload.size));
  }
  // A multipart upload that states no size (real campaign 0.7.6) is matched to a picked file on its name
  // alone: the guard never sees a file's content, so the size added nothing it could verify.
  else if(typeof upload.name==='string'){const named=nameDigest(upload.name);hit=approvals.find(a=>a.kind==='file'&&free(a)&&a.name===named);}
  if(!hit){return {seal:true};}
  consumed.push(hit.ref);
 }
 return consumed.length?{allow:true,approved:true,consumed}:{seal:false};
}
function contentDecision(details,policy,wire,approval,adapter){
 const protection=policy.config?.protection,masking=masks(policy),approvals=approvalList(approval);
 // `HEAD` and `OPTIONS` follow the `GET` rule because they carry NO payload:
 // a CORS preflight is a metadata request, and sealing it protected nothing
 // while killing the real request that follows it — the browser does not even emit
 // one. This is why the page used to load only halfway, with nothing explaining the
 // refusal (measured on 2026-09-16; a sealed `OPTIONS` request was observed on chatgpt.com).
 // `POST`, `PUT`, `PATCH` and `DELETE` stay outside this branch: they can carry
 // a body, and therefore go through the inspection below.
 if(providerRead(details,adapter)){
  // A `GET` whose DESTINATION is the covered provider passes, regardless of its
  // path and query, with `Referer` stripped. The previous rule only allowed a
  // navigation to the exact root: it sealed `/login`, `/chat/<id>` and
  // authentication redirects, so the site could no longer be opened at all under
  // content control (measured on 2026-09-16). Product decision of 2026-09-16:
  // widen it. The accepted risk is that a path or query can carry data TO THE
  // PROVIDER, which is in any case the intended recipient of prompts, while the
  // composer itself stays inspected.
  //
  // This branch only decides whether `Referer` is stripped: a read the provider's own
  // page makes at home goes out without the internal URL it came from. A `GET` to a
  // third-party host has no longer been sealed since the product decision of 2026-09-16
  // ("block only what is necessary"): it carries no prompt, and sealing it was showing
  // a banner for the page's telemetry. Risk accepted and recorded: a covered
  // page that called a third party with data in the URL would pass; the
  // `declarativeNetRequest` fallback, which has no blocking handler, keeps its own rules.
  return {allow:true,strip:true};
 }
 // A `file` route from the catalog — a MEASURED upload URL — is sealed under
 // file-upload blocking, before any read of the body.
 // An opaque upload route cannot prove which selected file it carries.
 // Dedicated DLP upload conditions therefore need a qualified private proof.
 if(wire?.file){return {seal:policy.config?.dlp_control?.enabled===true||!!protection?.block_uploads};}
 if(wire?.paste){return policy.config?.dlp_control?.enabled===true?{seal:true}:pasteDecision(wire,approvals,masking);}
 // Product decision of 2026-09-16: without masking, blocking file uploads seals
 // these routes and NOTHING ELSE — not a method (`PATCH` for account settings and the
 // model selector), not a host (third-party `GET`, API host), not the shape of a body.
 // Three releases the same day (0.5.30 to 0.5.32) showed that no heuristic holds:
 // a Cloudflare beacon in `text/plain`, NDJSON telemetry, a protobuf RPC, `fetch` sends
 // with a Blob body that `webRequest` only delivers as `error`, then the model-change
 // `PATCH` requests — each showing "the transport cannot be verified" for a send that
 // was not a file. The file picker is otherwise still intercepted in the page.
 // Under masking, everything that follows stays closed.
 if(!masking){return {seal:false};}
 // A draft posted to a sub-route of the send (`wireFacts`) is sealed without a notice or an event: the
 // person is typing, and the send itself is inspected. Approved text passes without spending the approval.
 if(wire?.draft&&details.requestBody){
  const quiet=!wire.loud;
  if(!wire.readable||wire.prose){return {seal:true,quiet};}
  if(!wire.groups.length){return {seal:policy.config?.dlp_control?.enabled===true,quiet};}
  return covering(wire.groups,approvals,policy.config?.dlp_control?.enabled===true)?{allow:true}:{seal:true,quiet};
 }
 // Under masking, same principle (product decision of 2026-09-16): only what CARRIES a
 // prompt is held back — a prompt route from the catalog, or a body shaped like a
 // prompt — and nothing else. Measured after a keyword block: compressed Datadog
 // telemetry and a claude.ai protobuf RPC were sealed in turn and showed a
 // second banner. The composer has already stopped or masked the text at the source; the
 // network guard only re-checks the request that carries it. Risk accepted and recorded:
 // a prompt route unknown to the catalog with an unreadable body would pass under masking.
 // Any other method on a prompt route that carries a body is a send too (PATCH, DELETE).
 if(!['POST','PUT'].includes(details.method)&&!(wire?.route&&details.requestBody)){return {seal:false};}
 // A body the synchronous path cannot read only goes out, on a prompt route,
 // within the window opened by an approval, for that tab and that document: this is
 // the case for claude.ai, which compresses its request body. Outside a prompt route, it passes.
 // A form route whose field is missing, repeated or not JSON (see `wireFacts`).
 if(wire?.malformed){return {seal:true};}
 if(!wire?.readable){return unreadableContentDecision(wire,approvals,policy.config?.dlp_control?.enabled===true);}
 // A send with no text at its route's paths (an image alone, an upload RPC, a retry with nothing
 // new) has nothing to compare: it passes unless prose travels elsewhere in its body
 // (`wireFacts`). Real campaign 0.7.3: sealing it made attachments impossible under masking.
 // A protobuf send reads every string of its body: prose outside its text paths seals it, approved or not.
 if(wire.route&&wire.prose){return {seal:true};}
 if(wire.route&&!wire.groups?.length&&Object.hasOwn(wire,'prose')){return {seal:policy.config?.dlp_control?.enabled===true};}
 if(!wire.texts.length&&!promptShaped(wire.body,wire.keys)){return {seal:policy.config?.dlp_control?.enabled===true&&!!wire.route};}
 // The text must be PRESENT, not merely equal: without this condition, a body shaped
 // like a prompt but carrying nothing at its rule's path yields an empty string,
 // and an approval for empty text — which an empty submission is enough to obtain —
 // would match it. The payload could then travel in any other field of the body.
 // Compared under the layout tolerance the composer write already accepts (line breaks,
 // non-breaking spaces, surrounding blanks): a rich editor's `innerText` doubles the
 // break between two paragraphs while the page sends one. Only whitespace differs, so
 // no masked content can travel through it. A text reduced to blanks matches nothing.
 // Every text path the body fills must carry the approved text (`groups`), not only the first:
 // a masked copy in one field must not cover a clear copy in another.
 const consumed=wire.texts.length?covering(wire.groups?.length?wire.groups:[wire.texts],approvals,policy.config?.dlp_control?.enabled===true):null;
 return consumed?{allow:true,approved:true,consumed}:{seal:true};
}
function heldService(policy,platforms){
 return platforms.filter(Boolean).map(a=>policy?.config?.services?.find(s=>s.enabled&&['block','redirect'].includes(s.mode)&&(s.id===a.id||s.domains?.includes(a.domain)))).find(Boolean)||null;
}
// A blocked or redirected service (real campaign 0.7.3: `redirect` cut the page like a block, and
// the browser showed its own error). Its page goes to the destination, or to the extension's notice
// page for a block or a destination that is not plain https or is itself held back. Everything
// else it loads stays cut, unannounced: the composer already refuses or redirects a send.
function serviceDecision(details,policy,service,base){
 const destination=service.mode==='redirect'&&!writtenPort(service.redirect_url)?urlOf(service.redirect_url):null,host=destination&&hostOf(destination).toLowerCase();
 const held=destination&&(destination.protocol!=='https:'||heldService(policy,[networkPlatform(destination.href)])||policy.config.services.some(s=>s.enabled&&['block','redirect'].includes(s.mode)&&s.domains?.some(d=>host===d||host.endsWith('.'+d))));
 const redirect=destination&&!held?destination.href:null,reason=redirect?'service_redirected':'service_blocked';
 if(details.type!=='main_frame'||details.method!=='GET'){return {...base,reason,quiet:true};}
 let service_host=base.provider;try{service_host=hostOf(new URL(details.url));}catch{/* the provider stays named */}
 return {...base,reason,page:redirect||'blocked',service_host};
}
function controlledRequestDecision(details,policy,wire,approval,adapter,u,base){
 const direct=(u&&apiHosts[hostOf(u)])||!u;
 const read=!!u&&['GET','HEAD','OPTIONS'].includes(details.method)&&!details.requestBody;
 if(direct&&masks(policy)&&!read){return {...base,reason:'control_unavailable'};}
 const verdict=contentDecision(details,policy,wire,approval,adapter);
 if(verdict.seal){return {...base,reason:'control_unavailable',...(verdict.quiet?{quiet:true}:{})};}
 if(verdict.allow){return {...base,allow:true,strip:!!verdict.strip,approved:!!verdict.approved,...(verdict.consumed?{consumed:verdict.consumed}:{})};}
 return null;
}
function unqualifiedNavigation(details,target,u){
 return target&&u?.protocol==='https:'&&!apiHosts[hostOf(u)]&&details.type==='main_frame'&&details.method==='GET'&&!details.requestBody&&!u.search&&(u.pathname==='/'||target.conversation.test(u.pathname));
}
// `scopeOf(platformId,url)`: what the catalogue says of this request for a provider whose
// prompt routes name their model in a header (`headerModelScope` in detection.js, passed
// in to keep that module out of this one's imports), or null. For such a provider only
// its prompt route is held to the model rule, and the decision is deferred to the
// header handler (`route`); the page's other requests (`scoped` without `route`) are not
// cancelled for a model.
export function requestDecision(details,policy,wire,approval,now=Date.now(),scopeOf=null){
 const target=networkPlatform(details.url),origin=networkPlatform(details.initiator||details.originUrl||details.documentUrl);
 const adapter=(origin&&ruleFor(policy,origin.id)&&origin.id!==target?.id)?origin:target||origin;if(!adapter){return null;}
 const fresh=policy&&Date.parse(policy.expires_at)>now,rule=ruleFor(policy,adapter.id);
 const base={platform_id:adapter.id,provider:adapter.domain,revision:policy?.revision};
 // A top-level visit is held for where it goes, not where it came from: leaving a held page is free.
 const held=heldService(policy,details.type==='main_frame'?[target]:[target,origin]);
 if(held){return serviceDecision(details,policy,held,base);}
 // Content restrictions apply to private web transports as well as public APIs.
 const controlled=contentControl(policy);
 if(fresh&&!rule&&!controlled){return null;}
 const u=urlOf(details.url);
 if(!fresh){return {...base,reason:'control_unavailable'};}
 const scope=rule&&typeof scopeOf==='function'?scopeOf(adapter.id,u):null;
 if(controlled){
  const verdict=controlledRequestDecision(details,policy,wire,approval,adapter,u,base);
  // An approved send is still a send: its model is checked on its headers too.
  if(verdict){return verdict.allow&&scope?.route?{...verdict,scoped:true,route:scope.route}:verdict;}
 }
 // Outside content control, a top-level navigation to the root or to a
 // conversation remains a navigation, not a request to qualify: this is the
 // compatibility that per-model rules have always had. Under content control,
 // the branch above has already decided.
 if(!controlled&&unqualifiedNavigation(details,target,u)){return null;}
 // The leeway of a header-qualified page covers its own provider and third parties, never
 // another covered provider: that one is decided on its body under its own rule.
 if(scope&&(!target||target.id===adapter.id)){return {...base,scoped:true,route:scope.route||null};}
 // A CORS preflight never names a model: refusing it `model_unknown` killed the allowed send behind it.
 if(details.method==='OPTIONS'&&!details.requestBody){return null;}
 const judged=scope?target:adapter,model=requestModel(details,judged.id),reason=modelDecision(ruleFor(policy,judged.id),model);
 return reason?{platform_id:judged.id,provider:judged.domain,revision:policy?.revision,reason,model:model||undefined}:null;
}
