const encoder=new TextEncoder(),decoder=new TextDecoder();
const MAX_EXCHANGE_MS=8000,pinFields=['installation','edition','origin','organization_anchor','signing_key'];
let issued=0,acceptedGeneration=-1,acceptedPin='';
let exchangeTail=Promise.resolve(),queued=0;
const standard=value=>{let text='';for(let i=0;i<value.length;i+=8192){text+=String.fromCodePoint(...value.subarray(i,i+8192));}return btoa(text);};
const decoded=value=>Uint8Array.from(atob(value),c=>c.codePointAt(0));
const hex=bytes=>[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');
function samePin(a,b){return !!a&&!!b&&Object.keys(a).length===pinFields.length&&Object.keys(b).length===pinFields.length&&pinFields.every(key=>typeof a[key]==='string'&&a[key]===b[key]);}
function pinId(pin){return pinFields.map(key=>pin[key]).join('\u0000');}
function elapsed(startPerf,startWall){const perf=performance.now()-startPerf,wall=Date.now()-startWall;if(!Number.isFinite(perf)||wall<0||Math.abs(perf-wall)>1000||perf>MAX_EXCHANGE_MS||wall>MAX_EXCHANGE_MS){throw new Error('broker response expired');}return Math.max(perf,wall);}
async function managedPin(api){let managed;try{managed=await api.storage.managed.get('milvago_pin');}catch{throw new Error('managed pin unavailable');}if(!managed?.milvago_pin){throw new Error('managed pin unavailable');}let pin;try{pin=JSON.parse(managed.milvago_pin);}catch{throw new Error('managed pin invalid');}if(!samePin(pin,pin)){throw new Error('managed pin invalid');}return pin;}
export async function pinAuthority(pin){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(JSON.stringify(pinFields.map(key=>pin[key]))))));}
export async function currentAuthority(api){const managed=await api.storage.managed?.get('milvago_pin');if(!managed?.milvago_pin){return null;}return pinAuthority(await managedPin(api));}
export function broker(api,send,inner,expectedAuthority){
 // Serialize independent tab, policy and telemetry exchanges. Queue time consumes
 // the existing deadline, and cannot renew an authorization or the grace period.
 if(queued>=64){return Promise.reject(new Error('broker queue full'));}
 const startPerf=performance.now(),startWall=Date.now();queued++;
 let expired=false,timer;
 const check=()=>{if(expired){throw new Error('broker response expired');}return elapsed(startPerf,startWall);};
 const job=exchangeTail.then(()=>exchange(api,send,inner,expectedAuthority,startPerf,startWall,check));
 const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{expired=true;reject(new Error('broker response expired'));},MAX_EXCHANGE_MS);});
 const operation=Promise.race([job,deadline]).finally(()=>{expired=true;clearTimeout(timer);queued--;});
 exchangeTail=operation.catch(()=>{});
 return operation;
}
async function exchange(api,send,inner,expectedAuthority,startPerf,startWall,check){
 check();
 const order=++issued,pin=await managedPin(api);check();
 const authority=await pinAuthority(pin);check();if(expectedAuthority!==undefined&&expectedAuthority!==authority){throw new Error('browser authority changed');}
 inner={...inner,expected_authority:authority};
 const rawBody=encoder.encode(JSON.stringify(inner)),body=standard(rawBody),digest=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',rawBody)));
 check();if(!samePin(pin,await managedPin(api))){throw new Error('managed pin changed before exchange');}check();
 const answer=await send({protocol:2,op:'browser_request',body});check();
 if(!answer?.ok||answer.protocol!==2||typeof answer.signed?.payload!=='string'||typeof answer.signed?.signature!=='string'){throw new Error('broker response unavailable');}
 const key=await crypto.subtle.importKey('raw',decoded(pin.signing_key),{name:'Ed25519'},false,['verify']),raw=decoded(answer.signed.payload);
 if(!await crypto.subtle.verify('Ed25519',key,decoded(answer.signed.signature),raw)){throw new Error('broker signature rejected');}
 let value;try{value=JSON.parse(decoder.decode(raw));}catch{throw new Error('broker payload invalid');}
 if(value.kind!=='milvago.browser-response.v2'||value.protocol!==2||value.challenge!==inner.challenge||value.request_hash!==digest||!samePin(value.pin,pin)||!['connected','grace','blocked'].includes(value.mode)||!Number.isSafeInteger(value.generation)||value.generation<0){throw new Error('broker response rejected');}
 const reread=await managedPin(api);check();if(!samePin(pin,reread)){throw new Error('managed pin changed');}const spent=elapsed(startPerf,startWall);
 const identity=pinId(pin);if(identity!==acceptedPin){acceptedPin=identity;acceptedGeneration=-1;}if(order<issued||value.generation<acceptedGeneration){throw new Error('broker response replayed');}acceptedGeneration=value.generation;
 if(value.mode==='grace'&&(!Number.isSafeInteger(value.remaining_ms)||value.remaining_ms<=0||value.remaining_ms>300000||value.remaining_ms<=spent)){throw new Error('broker grace expired');}
 return {legacy:false,...value,authority,remaining_ms:value.mode==='grace'?Math.floor(value.remaining_ms-spent):0};
}
export function challenge(){return standard(crypto.getRandomValues(new Uint8Array(32)));}
