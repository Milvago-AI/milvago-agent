import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const pin={installation:'deadline-fixture',edition:'community',origin:'https://example.test',organization_anchor:'fixture',signing_key:publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
const api={storage:{managed:{get:async()=>({milvago_pin:JSON.stringify(pin)})}}};
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const inner=challenge=>({protocol:2,op:'browser_policy',tool:'chrome',challenge});
function response(request,generation){
 const raw=Buffer.from(request.body,'base64'),body=JSON.parse(raw);
 const payload=Buffer.from(JSON.stringify({kind:'milvago.browser-response.v2',protocol:2,pin,challenge:body.challenge,request_hash:createHash('sha256').update(raw).digest('hex'),generation,mode:'connected',remaining_ms:0,reply:{ok:true}}));
 return {ok:true,protocol:2,signed:{payload:payload.toString('base64'),signature:sign(null,payload,privateKey).toString('base64')}};
}
test('hung send expires and releases queue; late generation cannot poison recovery',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const {broker}=await import('./broker.js?deadline-send');
 const started=deferred(),held=deferred();let original,calls=0;
 const pending=broker(api,request=>{calls++;original=request;started.resolve();return held.promise;},inner('hung'));
 const rejected=assert.rejects(pending,/expired/);
 await started.promise;t.mock.timers.tick(8000);await rejected;
 assert.equal((await broker(api,async request=>{calls++;return response(request,2);},inner('fresh'))).generation,2);
 assert.equal(calls,2);
 held.resolve(response(original,999));await new Promise(r=>setImmediate(r));
 assert.equal((await broker(api,async request=>response(request,3),inner('after-late'))).generation,3);
});
test('expired pin read cannot send late or keep later exchanges blocked',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const {broker}=await import('./broker.js?deadline-pin');
 const started=deferred(),held=deferred();let calls=0;
 const stalled={storage:{managed:{get:()=>{started.resolve();return held.promise;}}}};
 const pending=broker(stalled,async request=>{calls++;return response(request,999);},inner('stalled-pin'));
 const rejected=assert.rejects(pending,/expired/);
 await started.promise;t.mock.timers.tick(8000);await rejected;
 assert.equal((await broker(api,async request=>response(request,2),inner('recovered'))).reply.ok,true);
 held.resolve({milvago_pin:JSON.stringify(pin)});
 await new Promise(r=>setImmediate(r));assert.equal(calls,0);
});
