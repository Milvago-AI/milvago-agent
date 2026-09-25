import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('./popup.js',import.meta.url),'utf8');
async function render(language,status,stored={}){const label={textContent:''},document={documentElement:{},querySelector:s=>s==='#status'?label:{addEventListener(){}}};vm.runInNewContext(source,{document,navigator:{language},chrome:{storage:{local:{get:async()=>({status,...stored})}},runtime:{sendMessage:async()=>({ok:true})}},setInterval(){},Date});await new Promise(resolve=>setImmediate(resolve));return {text:label.textContent,language:document.documentElement.lang};}
const active={connected:true,online:true,updated_at:new Date().toISOString(),expires_at:'2099-01-01T00:00:00Z',content_control:'unavailable',content_control_reason:'managed_extension_required'};
for(const [language,expected]of [['fr','Contrôle sélectif'],['en','Selective content'],['es','Control selectivo'],['pt-BR','Controle seletivo']]){test('popup renders unavailable content control in '+language,async()=>{const output=await render(language,active);assert.equal(output.language,language);assert.ok(output.text.includes(expected),output.text);assert.ok(!output.text.includes('Protection active'));});}
test('a malformed local lease never displays a connected protection state',async()=>{assert.equal((await render('en',{...active,expires_at:'invalid'})).text,'Local validation expired. Refresh to check protection.');});
// An unmanaged installation (no pin) degrades protection: the popup states it.
for(const [language,expected]of [['fr','non gérée'],['en','Unmanaged'],['es','no administrada'],['pt-BR','não gerenciada']]){test('popup warns about an unmanaged installation in '+language,async()=>{const output=await render(language,{...active,managed:false});assert.ok(output.text.includes(expected),output.text);});}
test('a managed installation carries no degraded warning',async()=>{const output=await render('fr',{...active,managed:true});assert.ok(!output.text.includes('non gérée'),output.text);});
// A failing DNR fail-closed seal leaves `seal_failed` set; the popup states it, even
// when the agent is unreachable, and falls silent as soon as the worker has cleared it
// (successful seal or successful refresh: see background.test.js).
for(const [language,expected]of [['fr','verrouillage réseau'],['en','network seal'],['es','sellado de red'],['pt-BR','selo de rede']]){test('popup reports a failed fail-closed seal in '+language,async()=>{const output=await render(language,{connected:false},{seal_failed:true});assert.ok(output.text.includes(expected),output.text);});}
test('a cleared seal flag carries no seal warning',async()=>{const output=await render('en',active,{seal_failed:false});assert.ok(!output.text.includes('network seal'),output.text);});
