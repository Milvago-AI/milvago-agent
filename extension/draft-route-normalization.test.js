import test from 'node:test';
import assert from 'node:assert/strict';
import {wireFacts} from './detection.js';

test('draft routes retain case, decoded, repeated and trailing slash normalization',t=>{
 const previous=globalThis.MilvagoAdapters;
 t.after(()=>{globalThis.MilvagoAdapters=previous;});
 globalThis.MilvagoAdapters={resolve:()=>({drafts:[{host:'synthetic.example',path:'/draft',field:'synthetic_text'}]})};
 const catalog={providers:[],heuristics:{keys:[]}};
 const check=path=>{
  const url=new URL('https://synthetic.example'+path);
  const details={url:url.href,initiator:'https://chatgpt.com/',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({synthetic_text:'Synthetic draft text'})).buffer}]}};
  return wireFacts(details,catalog,url);
 };
 for(const path of ['/draft','/DRAFT/','//draft///','/%64raft/%2F','/draft'+'/'.repeat(120000)]){
  const facts=check(path);assert.equal(facts.draft,true,path.slice(0,80));
  assert.deepEqual(facts.groups.map(group=>Array.from(group)),[['Synthetic draft text']],path.slice(0,80));
 }
 const facts=check('/draft'+'/'.repeat(120000)+'x');
 assert.notEqual(facts.draft,true);
});
