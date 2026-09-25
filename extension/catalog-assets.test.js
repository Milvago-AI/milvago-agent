import test from 'node:test';
import assert from 'node:assert/strict';
import {requestDecision} from './model-access.js';
// `model-access.js` imports `adapters.js`, which sets `globalThis.MilvagoAdapters` with the
// factory adapters — including the eighth field, the assets hosts measured on the site.
const A=globalThis.MilvagoAdapters;
// Under masking: this is where the "at the provider" rule decides a third-party `GET` from
// a covered page. Under file blocking alone, nothing else is sealed outside the
// `file` routes (product decision of 2026-09-16), so the assets host makes no difference there.
const policy={version:3,revision:190,expires_at:'2099-01-01T00:00:00Z',config:{services:[],model_access:[],collection:{enabled:false},privacy:{enabled:true}}};
const provider={id:'claude',label:'claude',domains:['claude.ai'],aliases:[],conversation_path:'/chat/*',conversation_segment:1,dom:{editor:'[role="textbox"]',send:'button',response:'[data-x]'},network:[],qualified_at:'2026-09-11T00:00:00Z'};
const served=extra=>({providers:[{...provider,...extra}],native_tools:[],heuristics:{keys:[],mime_types:[]}});
const asset=url=>requestDecision({url,method:'GET',type:'script',requestId:'a',initiator:'https://claude.ai'},policy);

// Measured on 2026-09-16 in a live 0.5.29 worker, inspected via CDP: the served catalog
// (revision 9) did not carry `asset_hosts`, so `applyCatalog` rebuilt `claude` with
// `assets: []`, and the 60 requests to `assets-proxy.anthropic.com` were sealed — while
// the same capture replayed WITHOUT a served catalog, on the factory adapters, sealed
// none of them. This test applies a served catalog before deciding, the way the worker does.
test('un catalogue servi sans asset_hosts garde les hôtes d\'assets d\'usine',()=>{
 try{
  A.applyCatalog(served({}));
  assert.deepEqual(A.adapters.find(a=>a.id==='claude').assets,['assets-proxy.anthropic.com','s-cdn.anthropic.com'],'plancher d usine conservé');
  const named=asset('https://assets-proxy.anthropic.com/claude-ai/v2/assets/v1/index.js');
  assert.equal(named?.allow,true,'hôte d assets d usine autorisé sous catalogue servi');
  assert.equal(named?.strip,true,'Referer retiré');
  // The floor does not open the neighboring domain: only the measured host is "at the
  // provider" (stripping `Referer`); the neighbor is not, without being sealed either.
  assert.equal(asset('https://autre.anthropic.com/x.js'),null,'voisin non nommé : ni chez lui, ni scellé');
  // An explicitly empty served list does not remove the measurement embedded in the signed extension.
  A.applyCatalog(served({asset_hosts:[]}));
  assert.equal(asset('https://assets-proxy.anthropic.com/x.js')?.allow,true,'liste servie vide = plancher');
 }finally{A.applyCatalog(null);}
});

test('un catalogue servi qui nomme un hôte l\'AJOUTE à la liste d\'usine',()=>{
 try{
  A.applyCatalog(served({asset_hosts:['cdn.example.test','assets-proxy.anthropic.com',42]}));
  assert.deepEqual(A.adapters.find(a=>a.id==='claude').assets,['assets-proxy.anthropic.com','s-cdn.anthropic.com','cdn.example.test'],'union sans doublon, valeurs non textuelles ignorées');
  assert.equal(asset('https://cdn.example.test/x.js')?.allow,true,'hôte servi autorisé');
  assert.equal(asset('https://assets-proxy.anthropic.com/x.js')?.allow,true,'hôte d usine toujours autorisé');
  // A served provider unknown to the factory has only what the catalog names for it.
  A.applyCatalog({providers:[{...provider,id:'autre',domains:['autre.test'],asset_hosts:['cdn.autre.test']}],native_tools:[],heuristics:{keys:[],mime_types:[]}});
  assert.deepEqual(A.adapters.find(a=>a.id==='autre').assets,['cdn.autre.test']);
 }finally{A.applyCatalog(null);}
 // Falling back to factory restores the measured list unchanged.
 assert.deepEqual(A.adapters.find(a=>a.id==='claude').assets,['assets-proxy.anthropic.com','s-cdn.anthropic.com']);
});
