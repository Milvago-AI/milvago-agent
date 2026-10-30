import './adapters.js';
import {strictJSON,hostOf} from './model-access.js';
export const BODY_LIMIT=128*1024;
// Ceiling of the DECOMPRESSED body, distinct from the transmitted body's ceiling. Measured on
// claude.ai on 2026-09-14: 21,191 bytes on the wire render 108,884 bytes, of which 100 KB
// are MCP tool definitions rather than prompt. A workstation with a few more connectors would
// cross 128 KiB and silently lose the model column again.
export const INFLATED_LIMIT=1024*1024;
// The account states a catalogue rule may state for its route.
export const SESSIONS=['signed_in','signed_out'];
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
// measured on 2026-09-15) and other form sends were therefore unreadable, and no catalogue rule
// could do anything about it. FILE content never appears in `formData` and is
// never read: only text fields are exposed.
// `all` (the blocking guard): every field is kept, in an object without prototype, so that text under a
// key no path could name (`a[b][]`, `a.b`) is still read as prose rather than dropped unseen.
export function decodeForm(form,all=false){
 if(!form||typeof form!=='object'||Array.isArray(form)){return null;}
 const body=all?Object.create(null):{};let total=0,keys=0;
 for(const [key,values] of Object.entries(form)){
  // A key that a catalogue path could not name has no business being exposed:
  // `valuesAt` holds segments to that same shape.
  if(!Array.isArray(values)||!all&&(!/^[A-Za-z0-9_-]{1,64}$/.test(key)||['__proto__','constructor','prototype'].includes(key))){continue;}
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
 if(!body||typeof body!=='object'||!Array.isArray(fields)||!fields.length){return body;}
 // An array root is unwrapped by position: a form document shaped `[null,"<json>"]`
 // keeps its prompt inside the string at index 1.
 const out=Array.isArray(body)?[...body]:{...body};
 for(const field of fields.slice(0,4)){
  // `out[field]=…` on `__proto__` would write the object's prototype, not a field:
  // the catalogue is signed, but an engine does not rely on that alone.
  if(typeof field!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(field)||['__proto__','constructor','prototype'].includes(field)){continue;}
  const value=out[field];if(typeof value!=='string'){continue;}
  try{const parsed=strictJSON(value,BODY_LIMIT);if(parsed&&typeof parsed==='object'){out[field]=parsed;}}catch{/* the field stays the string it is */}
 }
 return out;
}
const RESERVED=['__proto__','constructor','prototype'];
// The text of a raw body, or null: bounded, uncompressed, strict UTF-8.
function rawText(raw){
 let bytes=0;
 for(const part of raw){if(!part?.bytes||part.file){return {text:null,body_bytes:null};}bytes+=part.bytes.byteLength;if(bytes>16*1024*1024){return {text:null,body_bytes:null};}}
 if(bytes>BODY_LIMIT){return {text:null,body_bytes:bytes};}
 const joined=new Uint8Array(bytes);let at=0;for(const part of raw){joined.set(new Uint8Array(part.bytes),at);at+=part.bytes.byteLength;}
 if(compressionOf(joined)){return {text:null,body_bytes:bytes};}
 try{return {text:new TextDecoder('utf-8',{fatal:true}).decode(joined),body_bytes:bytes};}catch{return {text:null,body_bytes:bytes};}
}
// A form route whose whole message travels as ONE JSON document in one field, sent as
// `<field>=<json>` in an `application/x-www-form-urlencoded` body.
// That field becomes the body every path of the rule reads from. Its name carries a dot,
// which `decodeForm` cannot expose (a path segment cannot name it), hence a field of
// the rule rather than a path. Exactly one value, or nothing: two would be ambiguous.
export function decodeFormField(details,field){
 const none={body:null,body_bytes:null};
 if(typeof field!=='string'||!/^[A-Za-z0-9._-]{1,64}$/.test(field)||RESERVED.includes(field)){return none;}
 const request=details?.requestBody;
 if(!request||typeof request!=='object'||request.error){return none;}
 let values,body_bytes=null;
 if(request.formData&&typeof request.formData==='object'&&!Array.isArray(request.formData)){
  values=Object.hasOwn(request.formData,field)?request.formData[field]:undefined;
 }else if(Array.isArray(request.raw)){
  // Chrome only fills `formData` when the request declared a form type: the same
  // fields sent without it arrive as bytes.
  const read=rawText(request.raw);body_bytes=read.body_bytes;
  if(read.text===null){return {body:null,body_bytes};}
  try{values=new URLSearchParams(read.text).getAll(field);}catch{return {body:null,body_bytes};}
 }
 if(!Array.isArray(values)||values.length!==1||typeof values[0]!=='string'){return {body:null,body_bytes};}
 try{return {body:strictJSON(values[0],BODY_LIMIT),body_bytes};}catch{return {body:null,body_bytes};}
}
// Ceiling of a header value read as JSON: a model header measured so far is about 300 bytes.
export const HEADER_LIMIT=4096;
// The JSON document a request header carries, or undefined. Exactly one header of that
// name, or nothing: a repeated header is ambiguous.
export function headerJSON(headers,name){
 if(!Array.isArray(headers)||typeof name!=='string'||!/^[a-z0-9-]{1,64}$/.test(name)){return undefined;}
 const found=headers.slice(0,256).filter(h=>h&&typeof h==='object'&&typeof h.name==='string'&&h.name.toLowerCase()===name);
 if(found.length!==1||typeof found[0].value!=='string'){return undefined;}
 try{return strictJSON(found[0].value,HEADER_LIMIT);}catch{return undefined;}
}
export const MODEL_SHAPE=/^[A-Za-z0-9._:/-]{1,200}$/;
const CANONICAL_MODEL=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
// A provider that names its models with opaque identifiers (`0123456789abcdef`)
// gets them translated by the rule's `model_map`. An identifier the map does not know is
// still reported, prefixed with the provider (`<provider>:<id>`), so a new model shows up in
// the console instead of disappearing; a mapped name never carries `:`, so the two forms
// cannot collide.
export function canonicalModel(raw,rule,providerId){
 if(typeof raw!=='string'||!MODEL_SHAPE.test(raw)){return undefined;}
 const map=rule?.model_map;
 if(!map||typeof map!=='object'||Array.isArray(map)){return raw;}
 if(Object.hasOwn(map,raw)){const value=map[raw];return typeof value==='string'&&CANONICAL_MODEL.test(value)?value:undefined;}
 return raw.length<=64&&typeof providerId==='string'&&/^[a-z0-9][a-z0-9._-]{0,63}$/.test(providerId)?providerId+':'+raw:undefined;
}
// A bounded generic protobuf reader, for a route whose body is binary protobuf (`body_format`).
// Without the schema, every field becomes a list under its number (a repeated field and a single
// one look alike on the wire), in an object without prototype. A length-delimited field is text
// when it is printable UTF-8, otherwise a nested message when it parses as one, otherwise text when
// it is UTF-8 with control characters (an ANSI escape, a vertical tab in a pasted text), otherwise an
// opaque value (`null`) up to PROTO_OPAQUE bytes. An opaque value that is mostly text once decoded
// loosely is also kept, control characters dropped, in `opaque` for the prose check: text hidden behind
// an invalid byte is still read. A Connect envelope (`application/connect+proto`,
// flag byte and length) is opened when uncompressed. Anything else -- truncated, a varint past ten
// bytes, field 0, a group, too deep, too many fields, a large opaque value -- is `null`: the body
// cannot be read, and a route that cannot be read is sealed.
// With `opaque` (the guard), the bytes of a message's fixed-width fields and wide varints are also
// read back together, in order: prose cut into numbers is prose. When they are not text, a message
// holding PROTO_NUMBERS of them or more (32 bytes or more) beside text or messages cannot be read
// (the captures hold one at most).
// shortcut: text cut into small varints (under 2^28) or spread over several messages is not read
// back; upgrade if a capture ever needs those.
const PROTO_DEPTH=32,PROTO_FIELDS=20000,PROTO_OPAQUE=1024,PROTO_NUMBERS=4;
const UNPRINTABLE=/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
class ProtoLimit extends Error {}
function protoVarint(u8,at,end){
 let value=0,scale=1;
 for(let i=0;i<10;i++){if(at>=end){return null;}const b=u8[at++];value+=(b&127)*scale;scale*=128;if(!(b&128)){return [value,at];}}
 return null;
}
function protoUTF8(u8){try{return new TextDecoder('utf-8',{fatal:true}).decode(u8);}catch{return null;}}
// Mostly text once loosely decoded, control characters dropped: a binary value (an id, a key, a
// timestamp) is mostly control and replacement characters, and read as prose it would seal sends at random.
function looseText(bytes){const loose=new TextDecoder().decode(bytes),kept=loose.replaceAll(CONTROLS,'');return kept.length*8>=loose.length*7?kept:null;}
// A varint's value as little-endian bytes, from its 7-bit groups (exact past 2^53).
function varintBytes(u8,from,to){const out=[];let acc=0,bits=0;for(let i=from;i<to;i++){acc|=(u8[i]&127)<<bits;bits+=7;if(bits>=8){out.push(acc&255);acc>>>=8;bits-=8;}}if(acc){out.push(acc);}return out;}
const CONTROLS=/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\uFFFD]/g;
function protoMessage(u8,start,end,depth,budget){
 if(depth>PROTO_DEPTH){throw new ProtoLimit('depth');}
 const out=Object.create(null),numbers=[];let at=start,count=0;
 while(at<end){
  if(--budget.fields<0){throw new ProtoLimit('fields');}
  const tag=protoVarint(u8,at,end);if(!tag){return null;}at=tag[1];
  const field=Math.floor(tag[0]/8),wire=tag[0]%8;
  if(field<1||field>536870911){return null;}
  let value;
  if(wire===0){const v=protoVarint(u8,at,end);if(!v){return null;}if(v[1]-at>=5){numbers.push(...varintBytes(u8,at,v[1]));count++;}[value,at]=v;}
  else if(wire===1||wire===5){const size=wire===1?8:4;if(end-at<size){return null;}numbers.push(...u8.subarray(at,at+size));count++;value=null;at+=size;}
  else if(wire===2){
   const length=protoVarint(u8,at,end);if(!length||length[0]>end-length[1]){return null;}
   const from=length[1],to=from+length[0];at=to;
   const bytes=u8.subarray(from,to),text=protoUTF8(bytes);
   if(text!==null&&!UNPRINTABLE.test(text)){value=text;}
   else{
    value=protoTrial(u8,from,to,depth+1,budget);
    if(value===null&&text!==null){value=text;}
    else if(value===null){
     if(to-from>PROTO_OPAQUE){throw new ProtoLimit('opaque');}
     const kept=looseText(bytes);if(kept!==null){budget.opaque?.push(kept);}
    }
   }
  }else{return null;}
  (out[field]||=[]).push(value);
 }
 if(budget.opaque&&count){const kept=looseText(Uint8Array.from(numbers));if(kept!==null){budget.opaque.push(kept);}else if(count>=PROTO_NUMBERS&&numbers.length>=32){
  // Numbers alone are no message: a random value (a key) parses as one now and then, and keeps its opaque reading.
  if(Object.values(out).flat().some(v=>v!==null&&typeof v!=='number')){throw new ProtoLimit('numbers');}
  return null;
 }}
 return out;
}
// A value tried as a message keeps the opaque readings of that trial only when it is one: a failed trial
// over a text (a length cutting an accent in two) must not leave pieces of it to be read as prose.
function protoTrial(u8,from,to,depth,budget){
 const trial={fields:budget.fields,opaque:budget.opaque&&[]};
 try{const message=protoMessage(u8,from,to,depth,trial);if(message){budget.opaque?.push(...trial.opaque);}return message;}
 finally{budget.fields=trial.fields;}
}
// Without the schema, a nested message whose bytes are all printable reads as a string (a prompt of 32 to
// 126 characters one level down, or a message built so): its text would be out of its path's reach. The
// rule's paths say which fields are messages, every segment but the last: a string met there is read again
// as the message the server reads. A value at the end of a path is never read again: a prompt that happens
// to parse as a message stays the text it is. Too many fields: the body cannot be read.
function protoPaths(body,rule,opaque){
 if(!body){return body;}
 const budget={fields:PROTO_FIELDS,opaque};
 try{
  for(const path of [...textCandidates(rule),rule.model_path,rule.conversation_path,rule.files_path].filter(p=>typeof p==='string'&&p)){
   let values=[body];
   for(const part of path.split('.').slice(0,-1)){
    const key=part.replace(/\[\*\]$/,'');
    values=values.flatMap(v=>{
     const list=v&&typeof v==='object'&&Object.hasOwn(v,key)?v[key]:null;if(!Array.isArray(list)){return [];}
     for(let i=0;i<list.length;i++){if(typeof list[i]==='string'){const bytes=new TextEncoder().encode(list[i]);list[i]=protoTrial(bytes,0,bytes.length,0,budget)||list[i];}}
     return list;
    }).slice(0,1024);
   }
  }
 }catch{return null;}
 return body;
}
function protoEnvelopes(u8){
 const parts=[];let at=0,total=0;
 while(at<u8.length){
  if(u8.length-at<5||u8[at]!==0){return null;}
  const length=((u8[at+1]<<24)>>>0)+(u8[at+2]<<16)+(u8[at+3]<<8)+u8[at+4];at+=5;
  if(length>u8.length-at){return null;}
  parts.push(u8.subarray(at,at+length));at+=length;total+=length;
 }
 // Concatenated protobuf messages merge: the payloads read as one.
 const joined=new Uint8Array(total);let to=0;for(const part of parts){joined.set(part,to);to+=part.length;}
 return joined;
}
// `opaque`, when given, receives the loose decoding of every opaque value.
export function decodeProtobuf(u8,opaque){
 try{
  if(!(u8 instanceof Uint8Array)||u8.length>BODY_LIMIT){return null;}
  // A message never starts with 0x00 or 0x01 (field 0): those open a Connect envelope.
  const payload=u8.length&&u8[0]<2?protoEnvelopes(u8):u8;
  return payload?protoMessage(payload,0,payload.length,0,{fields:PROTO_FIELDS,opaque}):null;
 }catch{return null;}
}
// A protobuf route with a `form_field` reads a WebChannel batch: a form whose fields ending with that
// name (`req0___data__`, `req1___data__`) each hold one base64 message. Each is read on its own, as the
// server reads it (joined, a length left open at the end of one swallowed the next, text and all), and
// their fields merged in order; the other fields come back in `rest`, which the guard reads as prose. A
// field that is not base64 or not a whole message, or a batch past BODY_LIMIT, cannot be read.
function protoFormBody(request,rule,opaque){
 let form=null,body_bytes=null;
 if(!request||request.error){return {body:null,body_bytes};}
 if(request.formData&&typeof request.formData==='object'&&!Array.isArray(request.formData)){form=request.formData;}
 else if(Array.isArray(request.raw)){
  const read=rawText(request.raw);body_bytes=read.body_bytes;if(read.text===null){return {body:null,body_bytes};}
  form={};try{for(const [key,value] of new URLSearchParams(read.text)){(form[key]||=[]).push(value);}}catch{return {body:null,body_bytes};}
 }else{return {body:null,body_bytes};}
 const rest=decodeForm(form,true);if(!rest){return {body:null,body_bytes};}
 const parts=[],suffix=rule.form_field.toLowerCase();let total=0;
 for(const key of Object.keys(rest)){
  if(!key.endsWith(rule.form_field)){continue;}
  const value=rest[key];delete rest[key];
  if(typeof value!=='string'||!/^[A-Za-z0-9+/_-]*={0,2}$/.test(value)){return {body:null,body_bytes};}
  let bytes;try{bytes=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));}catch{return {body:null,body_bytes};}
  total+=bytes.length;if(total>BODY_LIMIT){return {body:null,body_bytes};}
  parts.push(bytes);
 }
 // The field's name left anywhere else, in any case (`REQ0___DATA__`, `ofs=0;req0___data__=…` for a
 // parser splitting on `;`), may still be read by the server: as in the query (`queryBatch`), not readable.
 if(JSON.stringify(rest).toLowerCase().includes(suffix)){return {body:null,body_bytes};}
 const body=Object.create(null),budget={fields:PROTO_FIELDS,opaque};
 try{for(const part of parts){const message=protoMessage(part,0,part.length,0,budget);if(!message){return {body:null,body_bytes};}for(const [field,values] of Object.entries(message)){(body[field]||=[]).push(...values);}}}
 catch{return {body:null,body_bytes};}
 return {body:protoPaths(body,rule,opaque),rest,body_bytes};
}
// A batch field in the request's query: the server may read it there as in the body, where the guard
// never looks. The page never puts one there (real campaign 0.7.7): such a request cannot be read.
function queryBatch(details,rule){
 let url;try{url=new URL(details.url);}catch{return true;}
 const suffix=rule.form_field.toLowerCase();
 return [...url.searchParams.keys()].some(key=>key.toLowerCase().includes(suffix));
}
// A WebChannel session closes with `navigator.sendBeacon(url+'&TYPE=terminate','')` (measured in a provider's
// code, real campaign 0.7.7). `webRequest` gives `{error}` for that empty body as for a Blob; the beacon's
// `Content-Type` tells them apart, checked on the headers (`beaconHeaders`): an empty string is sent as
// `text/plain;charset=UTF-8`, a Blob under its own type, which the Blob lower-cases, and a beacon cannot
// set a header. Anything else in the request (a readable body, another TYPE) is read as usual.
// Firefox names the type `beacon` and gives the empty string as `{raw:[]}`; an empty Blob reads the same there,
// its lower-cased type is what refuses it (measured in Firefox 158 with a probe add-on, 2026-10-17).
function emptyBody(body){
 if(!body||typeof body!=='object'||body.formData){return false;}
 return body.error?!body.raw:Array.isArray(body.raw)&&body.raw.length===0;
}
export function emptyBeacon(details){
 if(details?.method!=='POST'||!['ping','beacon'].includes(details.type)||!emptyBody(details.requestBody)){return false;}
 try{return new URL(details.url).searchParams.getAll('TYPE').join(',')==='terminate';}catch{return false;}
}
export function beaconHeaders(headers){
 const types=(Array.isArray(headers)?headers:[]).filter(h=>typeof h?.name==='string'&&h.name.toLowerCase()==='content-type');
 return types.length===1&&types[0].value==='text/plain;charset=UTF-8';
}
// The terminate beacon of a batch route of the catalogue, whose headers must then be checked.
export function sessionBeacon(details,catalog){
 if(!emptyBeacon(details)){return false;}
 let url;try{url=new URL(details.url);}catch{return false;}
 // A variant of the route (`nearRoute`: case, final slash, sibling RPC) passes on its empty body as well
 // (`wireFacts`, `bodyModel`): its headers are checked the same, or a Blob of any content rode on it.
 const match=routeMatch(catalog,details,url)||nearAny(catalog,details,url);
 return !!(match?.rule.body_format==='protobuf'&&match.rule.form_field&&!queryBatch(details,match.rule));
}
function protobufBody(request,opaque,rule){
 if(rule?.form_field){return protoFormBody(request,rule,opaque);}
 const raw=request?.raw;
 if(!request||request.error||request.formData||!Array.isArray(raw)){return {body:null,body_bytes:null};}
 let bytes=0;for(const part of raw){if(!part?.bytes||part.file){return {body:null,body_bytes:null};}bytes+=part.bytes.byteLength;if(bytes>16*1024*1024){return {body:null,body_bytes:null};}}
 if(bytes>BODY_LIMIT){return {body:null,body_bytes:bytes};}
 const joined=new Uint8Array(bytes);let at=0;for(const part of raw){joined.set(new Uint8Array(part.bytes),at);at+=part.bytes.byteLength;}
 return {body:compressionOf(joined)?null:protoPaths(decodeProtobuf(joined,opaque),rule,opaque),body_bytes:bytes};
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
// It is what stops a plausible wrong answer: a provider may state its reasoning by *adding*
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
 if(raw?.formData){return {decoded:decodeForm(raw.formData,true)};}
 if(Array.isArray(raw?.raw)){return decodeRawSync(raw.raw);}
 return {decoded:null};
}
export function bodyTextSync(details,rule){
 const read=decodeBodySync(details.requestBody);
 if(!Object.hasOwn(read,'decoded')){return read;}
 const {decoded}=read;
 if(decoded===null||typeof decoded!=='object'){return {readable:decoded!==null,texts:[],body:decoded};}
 const body=unwrapFields(decoded,rule?.json_fields);
 return {readable:true,texts:rule?textsAt(body,rule):[],groups:rule?textGroups(body,rule):[],body,...(rule&&untextual(body,rule)?{malformed:true}:{})};
}
// What the catalogue can say about a request without awaiting anything: file route,
// readable body, carried text. `model-access.js` decides from this and therefore does not
// import this module — an import cycle in the blocking path would cost dearly at the
// first change in evaluation order.
export function wireFacts(details,catalog,url){
 const drafted=draftEndpoint(details,url);
 if(drafted){return subFacts(details,new Set([drafted.field]),null,false);}
 const file=!!matchRule(catalog,details,url,'file');
 if(file){return {file:true,readable:false,texts:[],body:null};}
 if(matchRule(catalog,details,url,'paste')){return {...pasteFacts(details),file:false,texts:[],body:null};}
 // A variant the server may still route to a prompt route (letter case, trailing slash,
 // another method) is guarded like the route: masking must not be stepped around by spelling.
 const match=routeMatch(catalog,details,url)||nearAny(catalog,details,url);
 if(match?.sub&&!match.rule.form_field&&match.rule.body_format!=='protobuf'){return subFacts(details,leafKeys(match.rule),match.rule);}
 const facts=routeFacts(details,match);
 // A sibling RPC of the route's directory is a send only when it carries text where the
 // route does: the provider's other calls there (a regeneration, a title) carry none, and
 // sealing them would break the page under masking.
 if(!match?.sibling||facts.groups.length){return textless(facts,match);}
 // A protobuf sibling without text at the send's paths is page traffic (a timeline stream), unless
 // the guard cannot read it or finds something other than text at those paths.
 // An empty body reaches `webRequest` as `error`, like a Blob: claude.ai loads
 // `GetNewConversationDefaults` that way on every `/new` (real campaign 0.7.4). A sibling named as a
 // read (`Get…`, `List…`) passes on it. Risk accepted: a Blob holding text sent to such a read.
 const empty=details.requestBody?.error&&/\/(?:Get|List)[A-Z][A-Za-z0-9]*$/.test(routedPath(url.pathname));
 // A form sibling of a batch route with prose in a plain field (not in a message) is a send in clear: sealed.
 if(match.rule.body_format==='protobuf'){return facts.malformed&&!empty||facts.formProse?facts:{file:false,route:false,readable:true,texts:[],groups:[],body:null};}
 // A sibling of a form route is sealed as the route would be when it carries the route's field
 // or a body the guard cannot read (compressed, a Blob, not UTF-8). A JSON route keeps the
 // page's compressed calls passing (claude.ai's retry_completion): accepted and recorded.
 const page=routeFacts(details,null),field=match.rule.form_field;
 const carries=!!details.requestBody&&(!page.readable||[details.requestBody.formData,page.body].some(b=>b&&typeof b==='object'&&Object.hasOwn(b,field)));
 // Text under the field name the route keeps its text in, anywhere in a readable body, is a draft
 // leaving by another call: compared to the approvals like a sub-route's, sealed with a notice if not
 // approved (`loud`: an unmeasured call, which must not fail silently).
 if(!field&&page.readable&&page.body&&typeof page.body==='object'){
  const texts=fieldStrings(page.body,leafKeys(match.rule));
  if(texts===null||texts.length){return {...page,draft:true,loud:true,readable:texts!==null,groups:texts?.length?[texts]:[],prose:false};}
 }
 if(!(field&&carries)){return page;}
 // A sibling's field has its own shape (an upload's ids where the send keeps its text): not
 // malformed for that. A field the guard cannot decode, or given twice, still is.
 return textless(facts.readable?{...facts,malformed:false}:facts,match);
}
// A paste route (`kind:"paste"`): the upload a provider makes at paste time when it turns a long
// paste into a file. The guard reads the files the body names, whether each is text, its declared
// size, and its content when the body carries it readable. Chrome never gives `webRequest` a file's
// content: a Blob or File body is `error`, a multipart file part is left out, `formData` holds its
// name (measured 2026-10-16). A text file (a `.txt` name or any `text/*` type: CSV, Markdown, code)
// is then matched on its name and size, to a file the person picked, or, named and typed as a paste
// upload, on its size to an approved paste (`model-access.js`). Each upload keeps its name and type.
const TEXT_FILE=/\.txt$/i,TEXT_TYPE=/^text\//i;
const NAME_KEYS=['file_name','filename','fileName','name'],TYPE_KEYS=['mime_type','client_resolved_mime_type','content_type','contentType','mimeType','type'],SIZE_KEYS=['file_size','fileSize','size','size_bytes'];
const UNREAD={paste:true,readable:false,uploads:[]};
function declaredUploads(body){
 const uploads=[];let budget=2000;
 const walk=(value,depth)=>{
  if(!value||typeof value!=='object'){return;}
  // Too large or too deep to read: an unknown text file, which nothing can match.
  if(--budget<0||depth>16){uploads.push({text:true});return;}
  if(Array.isArray(value)){for(const v of value){walk(v,depth+1);}return;}
  const pick=(keys,ok)=>keys.map(k=>Object.hasOwn(value,k)?value[k]:undefined).find(ok);
  const name=pick(NAME_KEYS,v=>typeof v==='string'),type=pick(TYPE_KEYS,v=>typeof v==='string'&&v.includes('/'));
  if(name!==undefined||type!==undefined){const size=pick(SIZE_KEYS,v=>v!==undefined);uploads.push({text:TEXT_FILE.test(name||'')||TEXT_TYPE.test(type||''),name,type,...(Number.isSafeInteger(size)?{size}:{})});}
  for(const v of Object.values(value)){walk(v,depth+1);}
 };
 walk(body,0);return uploads;
}
// A file part names its file; a text part holding prose is pasted text riding as a field.
// A file picked from disk reaches `webRequest` as its own element, `{file:<path>}`, never its bytes
// (measured 2026-10-17 on a provider's upload): `files` holds those paths, each standing as `mark` in the
// text. Such a part is the file its header names only when that name is the file's own (the path's last
// segment): a page sending a file from disk under an approved name is not read.
function multipartUploads(text,mark='',files=[]){
 const boundary=/^--([^\r\n]{1,200})\r\n/.exec(text)?.[1];if(!boundary){return null;}
 const uploads=[];let used=0;
 for(const part of text.split('--'+boundary)){
  const at=part.indexOf('\r\n\r\n');if(at<0){if(mark&&part.includes(mark)){return null;}continue;}
  const head=part.slice(0,at),value=part.slice(at+4).replace(/\r\n$/,''),name=/filename="([^"]*)"/i.exec(head)?.[1],type=/content-type:\s*([^\s;]+)/i.exec(head)?.[1]||'';
  if(mark&&value===mark){
   const path=files[used++];
   // `filename*` would name the file otherwise for the server (RFC 6266): not read. A POSIX path only
   // splits on `/`: `evil\notes.txt` is a whole file name there, not `notes.txt`.
   if(name===undefined||/filename\*/i.test(head)||typeof path!=='string'||path.split(path.startsWith('/')?'/':/[\\/]/).pop()!==name){return null;}
   uploads.push({text:TEXT_FILE.test(name)||TEXT_TYPE.test(type),name,type});
  }
  else if(mark&&part.includes(mark)){return null;}
  else if(name!==undefined){uploads.push({text:TEXT_FILE.test(name)||TEXT_TYPE.test(type),name,type,...(value?{content:value}:{})});}
  else if(prose(value)){uploads.push({text:true,content:value});}
 }
 return used===files.length?uploads:null;
}
// The text of a raw body whose file elements stand as `mark`, with their paths, or null.
function rawWithFiles(raw){
 const mark='\u0000'+crypto.randomUUID()+'\u0000',files=[],texts=[];let bytes=0;
 for(const part of raw){
  if(part?.file!==undefined){if(typeof part.file!=='string'||files.length>=16){return null;}files.push(part.file);texts.push(mark);continue;}
  if(!part?.bytes){return null;}bytes+=part.bytes.byteLength;if(bytes>BODY_LIMIT){return null;}
  const text=protoUTF8(new Uint8Array(part.bytes));if(text===null){return null;}texts.push(text);
 }
 return {text:texts.join(''),mark,files};
}
function formUploads(form){
 const uploads=[];
 for(const values of Object.values(form)){
  for(const value of Array.isArray(values)?values:[]){
   if(typeof value!=='string'){continue;}
   if(FILE_NAME.test(value)){uploads.push({text:TEXT_FILE.test(value),name:value});}else if(prose(value)){uploads.push({text:true,content:value});}
  }
 }
 return uploads;
}
function pasteFacts(details){
 const request=details?.requestBody;
 if(!request||typeof request!=='object'){return {paste:true,readable:true,uploads:[]};}
 if(request.error){return UNREAD;}
 if(request.formData&&typeof request.formData==='object'&&!Array.isArray(request.formData)){return {paste:true,readable:true,uploads:formUploads(request.formData)};}
 if(!Array.isArray(request.raw)){return {paste:true,readable:true,uploads:[]};}
 if(request.raw.some(part=>part?.file!==undefined)){const read=rawWithFiles(request.raw),files=read&&multipartUploads(read.text,read.mark,read.files);return files?{paste:true,readable:true,uploads:files}:UNREAD;}
 const {text}=rawText(request.raw);if(text===null){return UNREAD;}
 const parts=multipartUploads(text);if(parts){return {paste:true,readable:true,uploads:parts};}
 // Not JSON: the body is the uploaded text itself.
 try{return {paste:true,readable:true,uploads:declaredUploads(strictJSON(text,BODY_LIMIT))};}catch{return {paste:true,readable:true,uploads:[{text:true,content:text}]};}
}
// A route request with no text at its paths (an attachment sent alone, a retry with nothing new)
// carries `prose`: whether text travels elsewhere in its body, which keeps it sealed under masking.
function textless(facts,match){
 // A protobuf read already found prose outside the body's strings (opaque values, plain form fields): kept.
 return facts.route&&facts.readable&&!facts.groups.length?{...facts,prose:!!facts.prose||prose(facts.body,match?.rule)}:facts;
}
// A sub-route of a JSON send (`draft`): ChatGPT posts the draft being typed to
// `/backend-api/f/conversation/prepare` (`partial_query.content.parts`), before any inspection (real
// campaign 0.7.4). Text under the field name the route keeps its text in, at any depth, is compared to
// the approvals without spending them; other prose, or a body the guard cannot read, seals it.
// A sub-route body without that field but with prose elsewhere is a send of its own (an answer to a
// question the model asked, real campaign 0.7.6): each prose string is compared to the approvals, and a
// refusal is announced (`loud`) since the person did act. Prose that is not a string (a list of words, a
// key) still seals.
function subFacts(details,keys,rule=null,announce=true){
 const page=routeFacts(details,null);
 if(!details.requestBody){return page;}
 const texts=page.readable?fieldStrings(page.body,keys):null;
 const others=texts&&!texts.found?proseStrings(page.body):[];
 if(!texts||!others){return {...page,draft:true,readable:false,groups:[]};}
 return {...page,draft:true,groups:[...(texts.length?[texts]:[]),...others.map(text=>[text])],...(others.length&&announce?{loud:true}:{}),prose:prose(page.body,rule,new Set([...texts,...others]))};
}
// The strings of a body that read as prose on their own, or null when it is too large or deep to walk.
function proseStrings(body){
 const out=[];let budget=10000;
 const walk=(value,depth)=>{
  if(--budget<0||depth>40){return false;}
  if(typeof value==='string'){if(prose(value)&&!out.includes(value)){out.push(value);}return true;}
  if(!value||typeof value!=='object'){return true;}
  return Object.values(value).every(inner=>walk(inner,depth+1));
 };
 return walk(body,0)?out.slice(0,64):null;
}
// A provider page may post the draft being typed to a third-party host while the person types (a
// search-suggestion service): such an endpoint is named, with the field its text travels under, by the
// adapter of the page that calls it (`drafts`). Read like a sub-route of the send: sealed without a
// notice unless the text is the one just approved.
function draftEndpoint(details,url){
 const page=globalThis.MilvagoAdapters?.resolve(details.initiator||details.originUrl||details.documentUrl||'');
 if(!page?.drafts?.length||!details.requestBody){return null;}
 const host=hostOf(url),path=routedPath(url.pathname).toLowerCase().replace(/\/+$/,'');
 return page.drafts.find(d=>d.host===host&&glob(d.path.toLowerCase(),path))||null;
}
// The last segment of each text path of a rule: the field name its text travels under.
function leafKeys(rule){return new Set(textCandidates(rule).map(p=>typeof p==='string'?p.split('.').pop().replace(/\[\*\]$/,''):'').filter(Boolean));}
// The non-empty strings under `keys` anywhere in a body (`found` when a key is there at all), or null when
// it is too large or deep to walk.
function fieldStrings(body,keys){
 const out=[];let budget=10000;
 const walk=(value,depth)=>{
  if(--budget<0||depth>40){return false;}
  if(!value||typeof value!=='object'){return true;}
  for(const [key,inner] of Object.entries(value)){
   if(keys.has(key)&&!Array.isArray(value)){out.found=true;for(const s of [inner].flat()){if(typeof s==='string'&&s!==''){out.push(s);}}}
   if(!walk(inner,depth+1)){return false;}
  }
  return true;
 };
 return walk(body,0)?out:null;
}
// Prose: text a person wrote or a value they pasted, read through JSON held in strings. Words
// separated by blanks (or by `_` and invisible characters), a script written without spaces, a
// sensitive shape on its own (`@`, nine digits or more, an IBAN, a card as a JSON number), and the
// same once base64 or percent decoding gives readable text. Keys are read as well as values, and
// the words of a list read together. Identifiers, tokens, MIME types and file names are not prose:
// a file name is a value of four words or fewer, or any value under a `name` key. A body too
// large or too deep to walk counts as prose: it stays sealed.
// shortcut: a single plain word, or a lower-case snake_case run of eight words or fewer, hidden
// outside the path is not seen; the approval stays the guard for any text at the path.
// Two characters on each side, not `{2,}`: the same test, and linear (`{2,}` backtracked over a long
// run of letters, 24 s for 128 KiB of hex in the blocking handler).
const WORDS=/[\p{L}\p{N}]{2}\s+[\p{L}\p{N}]{2}/u,FILE_NAME=/^[^\n\/@]{1,120}\.[A-Za-z0-9]{2,5}$/,FILE_KEYS=['name','file_name','filename'];
const SENSITIVE=/@|(?<![\p{L}\p{N}])\d(?:[ \t.-]?\d){8,}(?![\p{L}\p{N}])|(?<![\p{L}\p{N}])[A-Z]{2}\d{2}[A-Z0-9]{8,}/u;
const SPACELESS=/[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}]{2,}/u;
const UUID=/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,IGNORABLE=/\p{Default_Ignorable_Code_Point}/gu;
// A lower-case kebab-case token is a page's flag (`features`: `beta-imagegen`, real campaign 0.7.7), not a word.
const LIST_WORD=/^(?![a-z]+(?:-[a-z]+)+$)[\p{L}\p{M}'’-]{2,}[.,;:!?]?$/u;
function luhn(digits){let sum=0;for(let i=0;i<digits.length;i++){let n=+digits[digits.length-1-i];if(i%2){n*=2;if(n>9){n-=9;}}sum+=n;}return sum%10===0;}
function decoded(value){
 const out=[];
 // A value decoding to control characters is binary that happens to be ASCII (ChatGPT's
 // `turnstileToken`, real campaign 0.7.4): read as prose, a stray `@` or a run around a form feed
 // sealed an image sent alone. Text hidden in base64 is printable; its rare controls read as blanks.
 // shortcut: text interleaved with controls (one in eight characters or more) is not read; upgrade if a capture shows it.
 // Text in UTF-16 (every other byte zero) is half controls as UTF-8: it is read as UTF-16 instead.
 if(/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(value)){try{
  const bytes=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/').replace(/=+$/,'').padEnd(Math.ceil(value.replace(/=+$/,'').length/4)*4,'=')),c=>c.charCodeAt(0));
  const wide=bytes.length%2===0?['le','be'].find((_,odd)=>bytes.every((b,i)=>i%2!==odd||b===0)):undefined;
  const text=new TextDecoder(wide?'utf-16'+wide:'utf-8',{fatal:true}).decode(bytes),kept=text.replaceAll(CONTROLS,'');
  if(kept.length*8>=text.length*7){out.push(text.replaceAll(CONTROLS,' '));}
 }catch{/* not base64 text */}}
 if(/%[0-9A-Fa-f]{2}/.test(value)){try{const text=decodeURIComponent(value.replaceAll('+',' '));if(text!==value){out.push(text);}}catch{/* not percent-encoded text */}}
 return out;
}
function prose(body,rule,skip=new Set()){
 const names=new Set([...(rule?.files_path?valuesAt(body,rule.files_path):[]),...skip]);
 let budget=10000;
 const text=(value,key,depth)=>{
  if(names.has(value)){return false;}
  if(/^\s*[[{]/.test(value)){try{return walk(strictJSON(value,BODY_LIMIT),key,depth+1);}catch{/* not JSON: read as text */}}
  if(FILE_NAME.test(value)&&(FILE_KEYS.includes(key)||value.trim().split(/\s+/).length<=4)){return false;}
  const flat=value.replace(UUID,' ').replace(IGNORABLE,' ');
  // `_` joins words only between three letter runs, and only when the value is not a lower-case
  // identifier of eight parts or fewer: a page's own field names and constants are written that way
  // (`ask_retry_or_continue_rate_limit`, six parts, real campaign 0.7.7). A sensitive shape inside
  // one (`iban_FR76…`, `carte_4970…`, `@`) is still read below. A run of them (`__`) or another
  // connector (`＿`, `‿`) joins words the same way: otherwise any prose written with one passed.
  const parts=flat.split(/\p{Pc}+/u),snake=/(?:^|\p{Pc})\p{L}{2,}\p{Pc}+\p{L}{2,}\p{Pc}+\p{L}{2,}(?:\p{Pc}|$)/u.test(flat)&&(/[^a-z0-9_]/.test(flat)||parts.length>=9);
  // `_` between the groups of a value is a separator too (`4970_1012_3456_7894`, `IBAN_FR76_3000_…`).
  if(WORDS.test(snake?parts.join(' '):flat)||SPACELESS.test(flat)||SENSITIVE.test(flat)||parts.length>1&&SENSITIVE.test(parts.join(' '))){return true;}
  return depth<40&&decoded(value).some(next=>text(next,key,depth+1));
 };
 const walk=(value,key,depth)=>{
  if(--budget<0||depth>40){return true;}
  if(typeof value==='string'){return text(value,key,depth);}
  if(typeof value==='number'){const digits=String(Math.abs(value));return Number.isInteger(value)&&(!Number.isSafeInteger(value)||digits.length>=13&&luhn(digits));}
  if(!value||typeof value!=='object'){return false;}
  if(Array.isArray(value)){
   const strings=value.filter(v=>typeof v==='string'&&!names.has(v));
   if(strings.filter(v=>LIST_WORD.test(v)).length>=3||SENSITIVE.test(strings.join(' ').replace(UUID,' '))){return true;}
   return value.some(v=>walk(v,key,depth+1));
  }
  return Object.entries(value).some(([k,v])=>text(k,'',depth)||walk(v,k,depth+1));
 };
 return walk(body,'',0);
}
// `route`: the request is a PROMPT route of the catalogue. Under masking, this — and a
// body shaped like a prompt — is what the decision keeps, and nothing else.
function routeFacts(details,match){
 if(match?.rule.body_format==='protobuf'){return {file:false,route:true,...protoTextSync(details,match.rule)};}
 if(match?.rule.form_field){const read=formTextSync(details,match.rule);return {file:false,route:true,...read,groups:read.groups||[]};}
 const read=bodyTextSync(details,match?.rule);
 return {file:false,route:!!match,readable:read.readable,texts:read.texts,groups:read.groups||[],body:read.body??null,...(read.malformed?{malformed:true}:{})};
}
function nearAny(catalog,details,url){
 for(const provider of catalog?.providers||[]){const near=nearRoute(provider,details,url);if(near){return near;}}
 return null;
}
// A send that carries its whole message in one form field (`form_field`) is read the same way
// the observation reads it, synchronously. A body that is present but whose field is
// missing, repeated or not JSON is `malformed`: the page itself never sends that, so it
// is sealed rather than given the approval window an unreadable (compressed) body gets,
// which would let any payload ride on a fresh approval.
function formTextSync(details,rule){
 const request=details?.requestBody;
 if(!request||typeof request!=='object'){return {readable:false,texts:[],body:null};}
 const {body}=decodeFormField(details,rule.form_field);
 if(body===null||typeof body!=='object'){return {readable:false,malformed:true,texts:[],body:null};}
 const unwrapped=unwrapFields(body,rule.json_fields);
 return {readable:true,texts:textsAt(unwrapped,rule),groups:textGroups(unwrapped,rule),body:unwrapped,...(untextual(unwrapped,rule)?{malformed:true}:{})};
}
// A protobuf send, read the same way the observation reads it. A body that is not protobuf is
// `malformed`, never given the approval window: the page always sends it readable. So is any value
// at a text path that is not text. Text is compared at the paths; every other string of the body
// is read as prose, which seals the send even when its text was approved.
function protoTextSync(details,rule){
 const request=details?.requestBody;
 if(rule.form_field&&queryBatch(details,rule)){return {readable:false,malformed:true,texts:[],groups:[],body:null};}
 if(rule.form_field&&emptyBeacon(details)){return {readable:true,texts:[],groups:[],body:Object.create(null),prose:false,beacon:true};}
 if(!request||typeof request!=='object'){return {readable:true,texts:[],groups:[],body:Object.create(null),prose:false};}
 const opaque=[],{body,rest}=protobufBody(request,opaque,rule);
 if(!body){return {readable:false,malformed:true,texts:[],groups:[],body:null};}
 const groups=textGroups(body,rule),stray=textCandidates(rule).some(candidate=>{const values=valuesAt(body,candidate);return values.length>=1024||values.some(v=>typeof v!=='string');});
 return {readable:true,texts:textsAt(body,rule),groups,body,prose:prose(body,rule,new Set(groups.flat()))||opaque.some(text=>prose(text))||!!rest&&prose(rest),...(rest&&prose(rest)?{formProse:true}:{}),...(stray?{malformed:true}:{})};
}
// The model a request names in a header, for a catalogue route that reads it there:
// `model` is what observation reports, `known` tells a name the rule's `model_map`
// translated (or a rule without a map) from an opaque id it does not know.
export function headerModel(match,headers){
 const {provider,rule}=match||{};
 if(!rule?.model_header){return {model:undefined,known:false};}
 const raw=only(headerJSON(headers,rule.model_header),rule.model_path,MODEL_SHAPE);
 const model=canonicalModel(raw,rule,provider.id);
 const map=rule.model_map;
 return {model,known:model!==undefined&&(!map||typeof map!=='object'||Object.hasOwn(map,raw))};
}
// A request path as the server will route it: percent-escapes decoded and runs of `/`
// collapsed, so `/Stream%47enerate` or `//_/…` cannot step around a route the
// catalogue names. A path that does not decode stays as sent.
function routedPath(pathname){
 let path=pathname;
 try{path=decodeURIComponent(pathname);}catch{/* kept as sent */}
 return path.replaceAll(/\/{2,}/g,'/');
}
// The prompt route of a request for the blocking guards, as sent or as the server routes it.
function routeMatch(catalog,details,url){
 return matchRule(catalog,details,url)||matchRule(catalog,details,{hostname:url.hostname,pathname:routedPath(url.pathname)});
}
// Per-model control of a web provider whose catalogue says, for EVERY prompt route, where
// the request names its model in a header — readable in the blocking header handler
// whatever the body encoding. Only those routes are then decided on the model; the
// page's other requests are not. `null`: the provider is not qualified this way, and
// the caller keeps failing closed on all of its traffic.
// A protobuf route naming its model in its body (`model_path`) qualifies too: the blocking body
// handler reads it (`route.body`). A session protocol names the model once, in the message that opens
// the session; a message without a model (the text sent into that session) is not decided on one.
export function headerModelProvider(catalog,platformId){
 const provider=catalog?.providers?.find(p=>p.id===platformId);
 const prompts=(provider?.network||[]).filter(n=>(n.kind||'prompt')==='prompt');
 return prompts.length&&prompts.every(n=>typeof n.model_header==='string'&&typeof n.model_path==='string'||n.body_format==='protobuf'&&typeof n.model_path==='string'&&n.model_path!=='')?provider:null;
}
// `url`: the request URL already held to https without port or credentials, or null,
// in which case the provider's traffic stays decided as before (failing closed).
export function headerModelScope(catalog,platformId,details,url){
 const provider=headerModelProvider(catalog,platformId);
 if(!provider||!url){return null;}
 const match=routeMatch(catalog,details,url),route=match?.provider.id===provider.id?match:nearRoute(provider,details,url);
 return {route:route&&!route.rule.model_header?{...route,body:bodyModel(route,details)}:route};
}
// The model a protobuf route names in its body: `absent` when the body names none (or there is no
// body), unknown when the body cannot be read or names it twice. Each opening of a batch opens its own
// session: two of them, one without its model, are unknown, never decided on the other's model.
function bodyModel(match,details){
 if(match.rule.form_field&&queryBatch(details,match.rule)){return {model:undefined,known:false};}
 if(!details.requestBody||match.rule.form_field&&emptyBeacon(details)){return {absent:true};}
 const {body}=protobufBody(details.requestBody,undefined,match.rule);
 if(!body){return {model:undefined,known:false};}
 // A body holding the message the model belongs to (the path's first segment) must name it: an opening
 // without its model is unknown, never absent.
 const values=valuesAt(body,match.rule.model_path),openings=valuesAt(body,match.rule.model_path.split('.')[0]).length;
 if(!values.length&&!openings){return {absent:true};}
 if(!values.length||openings>1){return {model:undefined,known:false};}
 const raw=values.length===1&&typeof values[0]==='string'&&MODEL_SHAPE.test(values[0])?values[0]:undefined;
 const model=canonicalModel(raw,match.rule,match.provider.id),map=match.rule.model_map;
 return {model,known:model!==undefined&&(!map||typeof map!=='object'||Object.hasOwn(map,raw))};
}
// A send the server may still route to a prompt route although the glob misses it: trailing
// slash, other letter case, another method, or a sibling RPC of the same service directory
// (`sibling`). It is decided on that route's header like the route itself, so a refused or
// absent model cannot step around the decision. The page's other traffic stays out of scope (a
// batch RPC endpoint beside the send): sealing it would break the page for an allowed model, and
// no prompt has been measured there. Accepted and recorded. A read (`GET`, `HEAD`) is a variant
// only on the route's own path and when it carries something (a body or a query); a preflight
// never is. `near`: not the route itself, so it never takes the DOM record of a send.
function nearRoute(provider,details,url){
 if(details.method==='OPTIONS'){return null;}
 const host=hostOf(url),path=routedPath(url.pathname).toLowerCase().replace(/\/+$/,''),read=['GET','HEAD'].includes(details.method);
 if(read&&!details.requestBody&&!url.search){return null;}
 const prompts=(provider.network||[]).filter(n=>(n.kind||'prompt')==='prompt'&&n.host===host);
 const same=prompts.find(n=>glob(n.path.toLowerCase(),path));
 if(same){return {provider,rule:same,near:true};}
 if(read){return null;}
 // A sub-route of the send itself (`<route>/prepare`) is a sibling read for drafts (`subFacts`).
 const sub=prompts.find(n=>glob(n.path.toLowerCase()+'/*',path));
 if(sub){return {provider,rule:sub,near:true,sibling:true,sub:true};}
 const rule=prompts.find(n=>glob(n.path.toLowerCase().replace(/[^/]*$/,'*'),path));
 return rule?{provider,rule,near:true,sibling:true}:null;
}
// The candidate text paths, tried in order, the first one to yield text winning.
// Shared by the observation and by the blocking decision.
function textCandidates(rule){return Array.isArray(rule.text_paths)&&rule.text_paths.length?rule.text_paths:[rule.text_path];}
function textsAt(body,rule){
 for(const candidate of textCandidates(rule)){
  const found=valuesAt(body,candidate).filter(v=>typeof v==='string');
  if(found.length){return found;}
 }
 return [];
}
// EVERY candidate path that carries text, one group per path, for the blocking guard: a
// provider may send the same prompt in two fields, and checking only the first let a masked
// copy ride beside a clear one. Empty strings carry nothing and are left out.
// A single-field text path holding anything but a string (number, null, object, list) is a
// shape the guard cannot compare: the request is sealed rather than let a copy ride in it. A
// list path (`[*]`) keeps its non-text elements out: a multimodal message lists attachment
// pointers beside its text.
function untextual(body,rule){
 return textCandidates(rule).some(candidate=>typeof candidate==='string'&&((candidate.includes('[*]')?strayAt(body,candidate.split('.')):valuesAt(body,candidate).some(v=>typeof v!=='string'))||valuesAt(body,candidate).length>=1024));
}
// Along a list path, every segment present must be the container the path expects, and every
// element of the final list either text or an attachment pointer: an object that is not of type
// `text` and holds no `text` string. Anything else could carry text the comparison never sees.
// A list, or lists together, holding more values than `valuesAt` reads is sealed for the same reason.
function strayAt(value,parts){
 if(!parts.length){return typeof value!=='string';}
 if(!value||typeof value!=='object'){return true;}
 const [part,...rest]=parts,each=part.endsWith('[*]'),key=each?part.slice(0,-3):part;
 if(!Object.hasOwn(value,key)){return false;}
 if(!each){return strayAt(value[key],rest);}
 const list=value[key];
 if(!Array.isArray(list)||list.length>1024){return true;}
 return list.some(item=>rest.length?strayAt(item,rest):typeof item!=='string'&&(!item||typeof item!=='object'||Array.isArray(item)||item.content_type==='text'||typeof item.text==='string'));
}
// A group read at one of the rule's `attachment_paths` is marked: a paste approval covers it, and
// only it (or a chip beside the draft in a list), never the draft a send approval covers.
// An attachment group also carries the file names written beside it (`names`): a text file the person
// picked travels with its name, and its approval is on that name and its size.
function textGroups(body,rule){
 const attached=Array.isArray(rule.attachment_paths)?rule.attachment_paths:[];
 return textCandidates(rule).map(candidate=>Object.assign(valuesAt(body,candidate).filter(v=>typeof v==='string'),attached.includes(candidate)?{attachment:true,names:siblingNames(body,candidate)}:{attachment:false})).filter(group=>group.join('')!=='');
}
function siblingNames(body,candidate){
 const parent=candidate.split('.').slice(0,-1).join('.');
 return parent?valuesAt(body,parent).flatMap(item=>item&&typeof item==='object'?Object.values(item).flat():[]).filter(v=>typeof v==='string'&&FILE_NAME.test(v)).slice(0,64):[];
}
// `headers`: the request headers, or a promise of them. `webRequest` only states them in
// `onBeforeSendHeaders`, after the body; it is awaited only by a rule that reads one.
export async function observeRequest(details,catalog,modelEnabled=false,headers=null){
 let url;try{url=new URL(details.url);if(url.protocol!=='https:'||url.username||url.password||url.port){return null;}}catch{return null;}
 const match=matchRule(catalog,details,url);
 if(!match){return null;}
 // A session's terminate beacon carries no message: no prompt, not even an empty one (real campaign 0.7.8).
 if(match.rule.form_field&&emptyBeacon(details)){return null;}
 const {provider,rule}=match,{body:decoded,body_bytes}=rule.body_format==='protobuf'?protobufBody(details.requestBody,undefined,rule):rule.form_field?decodeFormField(details,rule.form_field):await decodeBody(details);
 const body=unwrapFields(decoded,rule.json_fields);
 // One route can carry two body shapes: a provider may name the text `content[*].text` when
 // it opens a thread and `messageInput[*].text` afterwards. Two rules cannot settle
 // it — they match on method, host and path alone, and two matches make the whole
 // observation ambiguous — so a rule may name several candidate paths and the first
 // that yields text wins. It also absorbs a provider renaming a field between two
 // versions of its interface.
 const texts=textsAt(body,rule);
 const text=texts.join('');
 // A provider may state its model only in a request header holding JSON
 // (`model_header`); `model_path` then walks that
 // document instead of the body.
 let model;
 if(modelEnabled){
  if(rule.model_header){let list=null;try{list=await headers;}catch{/* no header: model unknown */}model=headerModel(match,list).model;}
  else{model=canonicalModel(only(body,rule.model_path,MODEL_SHAPE),rule,provider.id);}
 }
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
 // The account state is a property of the measured route, stated by the signed rule,
 // never read from the body: signed-out ChatGPT sends through `/unauth-mweb/` and names
 // no model, and this is what tells that exchange apart from an unknown model.
 const session=SESSIONS.includes(rule.session)?rule.session:undefined;
 // A protobuf route is an RPC carrying several actions (a session opening, an acknowledgement, a setting):
 // one read whole with no text and no file is no prompt. What it names (model, thread) is still kept for the
 // exchange, without an event. A JSON route keeps its event: no text there is a shape the catalogue missed.
 if(rule.body_format==='protobuf'&&body!==null&&body!==undefined&&text===''&&!files.length){return {provider,silent:true,model,effort,session,conversation_id:conversation};}
 return {provider,characters:texts.length?Array.from(text).length:0,characters_known:!!texts.length,body_bytes,model,effort,session,conversation_id:conversation,files,fingerprint:texts.length?await fingerprint(text):null};
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
  if(!p.attempted){const network=source==='network'?event:p.event,dom=source==='dom'?event:p.event;const merged={...p,event:{...dom,...network,correlation_id:dom.correlation_id||network.correlation_id,labels:[...new Set([...(dom.labels||[]),...(network.labels||[])])]},source:'both'};await this.commit(this.pending.map(row=>row===p?merged:row));p=merged;}
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
