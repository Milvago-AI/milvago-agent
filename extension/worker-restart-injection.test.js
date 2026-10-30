// Real campaign 0.7.11: an answer was never recorded. Measured by CDP on 2026-10-17: when the extension's worker
// starts again (the browser stops it when idle, any message wakes it), its first catalogue refresh executed
// adapters.js and capture.js again in every open provider tab, 0.4 s later; the new capture replaced the one that
// held the send just made (its correlation, its receipts, the answers it knew), so the answer streaming then and
// the request's receipt were lost. Content scripts are re-executed only for a catalogue the tabs do not run yet.
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
import {detectionRuntime} from './detection-runtime.js';

function browserState(){
 const session={},registered=[],executed=[];
 return {session,registered,executed,api:()=>({
  runtime:{getManifest:()=>({version:'0.7.11',content_scripts:[]})},
  storage:{local:{async get(){return {};},async set(){}},session:{async get(key){return {[key]:session[key]};},async set(value){Object.assign(session,value);}}},
  tabs:{async query(){return [{id:7,url:'https://chatgpt.com/c/synthetic'}];}},
  scripting:{
   async getRegisteredContentScripts(){return [...registered];},
   async unregisterContentScripts({ids}){for(const id of ids){registered.splice(registered.findIndex(s=>s.id===id),1);}},
   async registerContentScripts(list){registered.push(...list);},
   async executeScript(target){executed.push(target.target.tabId);},
  },
 })};
}
const worker=(api,revision)=>detectionRuntime(api,async()=>({ok:true,catalog:null,revision}),'chrome',()=>({config:{}}));

test('a restarted worker leaves the running content scripts alone, a new catalogue still reaches them',async()=>{
 const state=browserState();
 await worker(state.api(),4).refresh();
 assert.deepEqual(state.executed,[7],'first start: the open tab gets the scripts');
 // The browser stopped the idle worker; a message starts a new one, with nothing in memory.
 await worker(state.api(),4).refresh();
 await worker(state.api(),4).refresh();
 assert.deepEqual(state.executed,[7],'same catalogue after a restart: not executed again');
 await worker(state.api(),5).refresh();
 assert.deepEqual(state.executed,[7,7],'another catalogue revision: executed again');
});

test('without session storage the worker keeps executing them (unchanged fallback)',async()=>{
 const state=browserState(),api=()=>{const a=state.api();delete a.storage.session;return a;};
 await worker(api(),4).refresh();await worker(api(),4).refresh();
 assert.deepEqual(state.executed,[7,7]);
});
