import test from 'node:test';
import assert from 'node:assert/strict';
import {detectionRuntime} from './detection-runtime.js';
test('runtime keeps no browser session queue',async()=>{
 let sessionRead=false;globalThis.MilvagoAdapters={resolve:()=>null,applyCatalog:()=>{}};
 const api={runtime:{getManifest:()=>({version:'0.5.0',content_scripts:[]})},storage:{local:{async get(){return {}},async set(){}},session:{async get(){sessionRead=true;return{}},async set(){sessionRead=true;}}}};
 const runtime=detectionRuntime(api,async()=>({ok:true}),'browser',()=>({config:{}}));
 await runtime.refresh();assert.equal(sessionRead,false);
});
test('catalog request remains a service operation',async()=>{
 globalThis.MilvagoAdapters={resolve:()=>null,applyCatalog:()=>{}};const calls=[];
 const api={runtime:{getManifest:()=>({version:'0.5.0',content_scripts:[]})},storage:{local:{async get(){return {}},async set(){}}}};
 const runtime=detectionRuntime(api,async request=>{calls.push(request);return {ok:true,catalog:{providers:[]},revision:1};},'browser',()=>({config:{}}));
 await runtime.refresh();assert.deepEqual(calls[0],{op:'catalog',tool:'browser',authority:null});
});
