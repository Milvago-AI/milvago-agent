// Shared "managed installation" test fixture: a pin in storage.managed and a
// native bridge that speaks the broker protocol (signed Ed25519 challenge, monotonic
// generation), so the worker's handlers take the brokered path instead of the legacy
// fallback. Handlers are indexed by the INTERNAL op (browser_policy, browser_inspect,
// browser_submit, browser_event, browser_catalog, browser_health); an op outside
// the broker (which must receive nothing sensitive) is served by its direct name.
// `mode` is the one the broker signs into every response; `grace` also carries the
// `remaining_ms` the extension side of the broker requires.
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
export function managedBridge(handlers={},{mode='connected',remaining_ms=60000}={}){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const pin={installation:'00000000-0000-4000-8000-00000000000a',edition:'community',origin:'https://managed.example.invalid',organization_anchor:'anchor-managed',signing_key:publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
 let generation=0,unavailable=false;
 const calls=[];
 const sendNativeMessage=async(host,message)=>{
  if(unavailable){throw new Error('Offline');}
  if(message.op!=='browser_request'){calls.push({host,op:message.op,message});return handlers[message.op]?await handlers[message.op](message):{ok:true};}
  const raw=Buffer.from(message.body,'base64'),parsed=JSON.parse(raw);
  calls.push({host,op:parsed.op,message:parsed});
  const reply=handlers[parsed.op]?await handlers[parsed.op](parsed):{ok:true};
  const body=Buffer.from(JSON.stringify({kind:'milvago.browser-response.v2',protocol:2,pin,challenge:parsed.challenge,request_hash:createHash('sha256').update(raw).digest('hex'),generation:++generation,mode,...(mode==='grace'?{remaining_ms}:{}),reply}));
  return {ok:true,protocol:2,signed:{payload:body.toString('base64'),signature:sign(null,body,privateKey).toString('base64')}};
 };
 return {pin,calls,sendNativeMessage,setUnavailable(value){unavailable=value;}};
}
