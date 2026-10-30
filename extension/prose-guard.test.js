// Fourth review, I1: under masking, a send with no text at its route's paths (an image sent
// alone) passes unless text travels elsewhere in its body. The heuristic let through a lone
// sensitive value, a number, words split into a list, a key, joined by `_` or an invisible
// character, encoded, in a script written without spaces, or a sentence ending like a file name.
// Synthetic bodies shaped like the real ChatGPT send of an image.
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
import {wireFacts,headerModelScope} from './detection.js';
import {requestDecision} from './model-access.js';
import {factoryCatalog} from './detection-factory.js';

const policy={version:3,revision:7,expires_at:'2099-01-01T00:00:00Z',config:{services:[],model_access:[],collection:{enabled:false},privacy:{enabled:true}}};
const URL_='https://chatgpt.com/backend-api/f/conversation';
function decide(body){
 const details={requestId:'a',tabId:1,url:URL_,method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify(body)).buffer}]},initiator:'https://chatgpt.com'};
 const u=new URL(URL_);
 return requestDecision(details,policy,wireFacts(details,factoryCatalog,u),undefined,Date.now(),(id,uu)=>headerModelScope(factoryCatalog,id,details,uu));
}
const passes=decision=>!decision||decision.allow===true;
const image={content_type:'image_asset_pointer',asset_pointer:'file-service://file-0123456789abcdef01234567',size_bytes:48213,width:1024,height:768,fovea:null,metadata:{dalle:null,gizmo:null,sanitized:true}};
const send=(extra={},message={})=>({action:'next',messages:[{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',author:{role:'user'},create_time:1792154665.164,content:{content_type:'multimodal_text',parts:[image]},metadata:{attachments:[{id:'file-0123456789abcdef01234567',size:48213,name:'PXL_20261016_143211123.jpg',mime_type:'image/jpeg',width:1024,height:768}],selected_github_repos:[],serialization_metadata:{custom_symbol_offsets:[]}},...message}],
 conversation_id:'00000000-0000-4000-8000-000000000000',parent_message_id:'12345678-1234-4234-8234-123456789012',model:'gpt-5',timezone_offset_min:-240,timezone:'Europe/Paris',conversation_mode:{kind:'primary_assistant'},enable_message_followups:true,system_hints:[],supports_buffering:true,supported_encodings:['v1'],client_contextual_info:{is_dark_mode:false,time_since_loaded:42,page_height:900,page_width:1440,pixel_ratio:2,screen_height:1080,screen_width:1920},paragen_cot_summary_display_override:'allow',force_parallel_switch:'auto',...extra});
const SENTENCE='Le projet Orion rachete la societe Exemple le 3 mars';

test('an image sent alone, in the shape of the real send, passes',()=>{
 assert.ok(passes(decide(send())));
 assert.ok(passes(decide(send({},{metadata:{attachments:[{id:'file-synthetic',name:'Capture d’écran 2026-10-16 à 14.32.11.png',mime_type:'image/png'}]}}))),'a long file name under `name`');
});

test('a lone sensitive value or a sentence hidden elsewhere keeps the send sealed',()=>{
 for(const [label,extra] of [
  ['a sentence',{metadata:{note:SENTENCE}}],
  ['an IBAN alone',{metadata:{note:'FR7630006000011234567890189'}}],
  ['an e-mail alone',{metadata:{note:'jean.exemple@example.com'}}],
  ['a card in digits',{metadata:{note:'4111-1111-1111-1111'}}],
  ['a phone number',{metadata:{note:'06 12 34 56 78'}}],
  ['a card as a JSON number',{metadata:{n:4111111111111111}}],
  ['words as a list',{metadata:{w:SENTENCE.split(' ')}}],
  ['digits split across a list',{metadata:{w:['4111','1111','1111','1111']}}],
  ['a sentence as a key',{metadata:{[SENTENCE]:1}}],
  ['words joined by _',{metadata:{note:SENTENCE.replaceAll(' ','_')}}],
  ['lower-case words joined by _',{metadata:{note:SENTENCE.toLowerCase().replaceAll(' ','_')}}],
  ['words joined by U+200B',{metadata:{note:SENTENCE.replaceAll(' ','​')}}],
  ['words joined by U+3164',{metadata:{note:SENTENCE.replaceAll(' ','ㅤ')}}],
  ['a sentence in base64',{metadata:{note:Buffer.from(SENTENCE).toString('base64')}}],
  ['an IBAN in base64',{metadata:{note:Buffer.from('FR7630006000011234567890189').toString('base64url')}}],
  ['a sentence percent-encoded',{metadata:{note:encodeURIComponent(SENTENCE)}}],
  ['a sentence in Chinese',{metadata:{note:'奥利安项目收购示例公司'}}],
  ['a sentence in Japanese',{metadata:{note:'オリオン計画'}}],
  ['a sentence in Korean',{metadata:{note:'오리온프로젝트'}}],
  ['a sentence in Thai',{metadata:{note:'โครงการโอไรออน'}}],
  ['a sentence ending in .com',{metadata:{note:SENTENCE+' sur exemple.com'}}],
  ['a sentence ending in .fr',{metadata:{note:SENTENCE+' voir exemple.fr'}}],
  ['a sentence ending in .pdf',{metadata:{note:SENTENCE+' voir.pdf'}}],
  ['a file name of many words outside a name key',{metadata:{title:'Le projet Orion rachete Exemple.pdf'}}],
 ]){assert.equal(passes(decide(send(extra))),false,label);}
});

test('identifiers, tokens, file names and the page’s own fields are not prose',()=>{
 for(const [label,extra] of [
  ['ids and a token',{metadata:{a:'sess_7a2b3cf0faa14b6b',b:'c_8f3a2b1c0d9e7f65',c:'file-service://file-0123456789abcdef01234567',d:'image/png'}}],
  ['a random url-safe token',{metadata:{token:'q9Xv_2LmT0-zKpB7YwNcR4sDfGhJ8uEi'}}],
  ['a list of ids',{metadata:{ids:['c_8f3a2b1c0d9e7f65','r_0a1b2c3d4e5f6789','rc_fedcba9876543210']}}],
  ['a short list of words',{metadata:{w:['fr','en']}}],
  ['a lower-case snake-case value',{metadata:{mode:'paragen_cot_summary_display_override'}}],
  ['a timestamp in seconds',{metadata:{at:1792154665}}],
  ['a file name of four words',{metadata:{title:'Plan Orion version 2.pdf'}}],
  ['a percent-encoded identifier',{metadata:{q:'a%2Fb'}}],
 ]){assert.ok(passes(decide(send(extra))),label);}
});
