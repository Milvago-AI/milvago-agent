import assert from 'node:assert/strict';
import {generateKeyPairSync, sign, webcrypto} from 'node:crypto';
import test from 'node:test';
import {broker} from './broker.js';
const b64=value=>Buffer.from(value).toString('base64'),bytes=value=>new TextEncoder().encode(JSON.stringify(value));
const digest=value=>webcrypto.subtle.digest('SHA-256',value).then(x=>Buffer.from(x).toString('hex'));
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const pin={installation:'install-fixture',edition:'enterprise',origin:'managed',organization_anchor:'anchor-fixture',signing_key:b64(publicKey.export({format:'der',type:'spki'}).subarray(-32))};
const api={storage:{managed:{get:async()=>({milvago_pin:JSON.stringify(pin)})}}};
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function responder(inner,generation,changes={},wait=0){return async request=>{if(wait){await delay(wait);}const raw=Buffer.from(request.body,'base64'),payload={kind:'milvago.browser-response.v2',protocol:2,pin,challenge:inner.challenge,request_hash:await digest(raw),generation,mode:'connected',remaining_ms:0,reply:{ok:true},...changes},encoded=b64(bytes(payload));return {ok:true,protocol:2,signed:{payload:encoded,signature:b64(sign(null,Buffer.from(encoded,'base64'),privateKey))}};};}
const inner=n=>({protocol:2,op:'browser_event',challenge:b64(Buffer.alloc(32,n)),tool:'browser',delivery_id:'a3f6e911-89dd-43c8-9a9b-bd46e4e48064',event:{kind:'prompt'}});
test('broker accepts signed responses and rejects tampering, replay, and expiry', async () => {
const first=inner(1);assert.equal((await broker(api,await responder(first,10),first)).reply.ok,true);
await assert.rejects(()=>broker(api,async request=>{const value=await (await responder(inner(2),11))(request);value.signed.payload=b64(bytes({bad:true}));return value;},inner(2)),/signature rejected/);
const replay=await (await responder(inner(3),11))({body:b64(bytes(inner(3)))});await assert.rejects(()=>broker(api,async()=>replay,inner(4)),/response rejected/);
await assert.rejects(async()=>broker(api,await responder(inner(5),12,{mode:'grace',remaining_ms:0}),inner(5)),/grace expired/);
await assert.rejects(async()=>broker(api,await responder(inner(6),12,{mode:'grace',remaining_ms:300001}),inner(6)),/grace expired/);
await assert.rejects(async()=>broker(api,await responder(inner(7),9),inner(7)),/replayed/);
const slow=inner(8),fast=inner(9);const pending=broker(api,await responder(slow,14,{},30),slow);await delay(1);const concurrent=broker(api,await responder(fast,15),fast);assert.equal((await pending).reply.ok,true);assert.equal((await concurrent).reply.ok,true);
await assert.rejects(async()=>broker(api,await responder(inner(10),16,{},8100),inner(10)),/expired/);
let reads=0;const latePinApi={storage:{managed:{get:async()=>{if(++reads===2){await delay(8100);}return {milvago_pin:JSON.stringify(pin)};}}}};
await assert.rejects(async()=>broker(latePinApi,await responder(inner(11),17),inner(11)),/expired/);
console.log('broker signatures: tampering, replay, old generation and expiry rejected; valid concurrent exchanges serialized');
});
