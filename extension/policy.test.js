import test from 'node:test';import assert from 'node:assert/strict';import {trustedProvider,networkRules} from './policy.js';
test('browser sender cannot impersonate an AI provider with a suffix or user info',()=>{assert.equal(trustedProvider('https://chatgpt.com/'),'chatgpt.com');for(const u of ['https://chatgpt.com.other.test/','https://chatgpt.com@other.test/','http://chatgpt.com/']){assert.equal(trustedProvider(u),null);}});
test('expired policies cannot replace restrictions',()=>{assert.throws(()=>networkRules({version:1,revision:2,expires_at:'2000-01-01T00:00:00Z',rules:[]}));});
test('network restrictions remain within explicitly granted provider scope',()=>{const r=networkRules({version:1,revision:1,expires_at:'2099-01-01T00:00:00Z',rules:[{enabled:true,action:'block',domain:'chatgpt.com'},{enabled:true,action:'block',domain:'example.test'},{enabled:false,action:'block',domain:'claude.ai'}]});assert.equal(r.length,1);assert.deepEqual(r[0].condition.requestDomains,['chatgpt.com']);});

test('global service restrictions seal API destinations without a model rule or blocking permission',()=>{
 for(const mode of ['block','redirect']){
  const p={version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{model_access:[],services:[{id:'chatgpt',enabled:true,mode,domains:['chatgpt.com']},{id:'claude',enabled:true,mode,domains:['claude.ai']}]}};
  const domains=networkRules(p).flatMap(r=>r.condition.requestDomains);
  assert.ok(domains.includes('api.openai.com'));assert.ok(domains.includes('api.anthropic.com'));
 }
});
