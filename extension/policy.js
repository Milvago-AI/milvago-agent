import {factoryCatalog} from './detection-factory.js';
import './adapters.js';
import {apiHosts,modelRulesValid} from './model-access.js';
import {platformBlockRules} from './model-rules.js';
export const providers=[...globalThis.MilvagoAdapters.adapters.map(a=>a.domain),...Object.keys(globalThis.MilvagoAdapters.aliases)];
// Which browser runs the extension, as carried by every event and by the agent's
// liveness map. Sniffing the `browser` namespace is not a Firefox test any more:
// Chrome exposes it too since 137, and Chrome 152 was reported as Firefox in the
// console (2026-09-11). Client-hint brands come first because Edge, Brave and Chromium
// all carry "Chrome/" in their user agent; the user agent is the fallback where brands
// are absent (Firefox, older Chromium builds). The vocabulary is the agent's and the
// server's: chrome, edge, firefox, chromium, brave.
export function detectTool(nav=globalThis.navigator){
 const brands=(nav?.userAgentData?.brands||[]).map(b=>String(b?.brand||''));
 const has=pattern=>brands.some(b=>pattern.test(b));
 if(has(/Microsoft Edge/i)){return 'edge';}
 if(has(/Brave/i)){return 'brave';}
 if(has(/Google Chrome/i)){return 'chrome';}
 const ua=String(nav?.userAgent||'');
 if(/Firefox\//.test(ua)){return 'firefox';}
 if(/Edg\//.test(ua)){return 'edge';}
 if(has(/Chromium/i)||/Chrome\//.test(ua)){return 'chromium';}
 return 'chrome';
}
export function trustedProvider(value){return globalThis.MilvagoAdapters.resolve(value)?.domain||null;}
export function validPolicy(policy,now=Date.now()){return !!policy&&[1,2,3].includes(policy.version)&&modelRulesValid(policy)&&Number.isInteger(policy.revision)&&Number.isFinite(Date.parse(policy.expires_at))&&Date.parse(policy.expires_at)>now;}
export function networkRules(policy,now=Date.now()){
 if(!validPolicy(policy,now)){throw new Error('Policy unavailable');}
 const rules=policy.version===1?policy.rules:policy.config.services.flatMap(s=>(s.domains||[]).map(domain=>({...s,domain,action:s.mode})));
 const apiRules=policy.version===1?[]:policy.config.services.filter(s=>s.enabled&&['block','redirect'].includes(s.mode)).flatMap(s=>Object.entries(apiHosts).filter(([,platform])=>platform===s.id).map(([domain],index)=>({id:5000+policy.config.services.indexOf(s)*10+index,priority:2,action:{type:'block'},condition:{requestDomains:[domain]}})));
 const unknownRules=policy.version===1?[]:(policy.config.model_access||[]).filter(r=>r.channel==='browser'&&r.mode!=='off'&&!factoryCatalog.providers.some(p=>p.id===r.platform_id)).flatMap((r,i)=>(policy.config.services||[]).filter(s=>s.id===r.platform_id).flatMap(s=>[{id:30000+i*2,priority:200,action:{type:'block'},condition:{requestDomains:s.domains}},{id:30001+i*2,priority:200,action:{type:'block'},condition:{initiatorDomains:s.domains}}]));
 // Known platforms the organization blocks: an Enterprise rule set, empty in Community.
 const platformRules=policy.version===1?[]:platformBlockRules(policy);
 return [...apiRules,...unknownRules,...platformRules,...rules.filter(r=>r.enabled&&r.action==='block'&&(policy.version!==1||providers.includes(r.domain))&&typeof r.domain==='string'&&/^[a-z0-9.-]{1,253}$/.test(r.domain)).map((r,index)=>({id:index+1,priority:1,action:{type:'block'},condition:{requestDomains:[r.domain],resourceTypes:['main_frame','sub_frame','xmlhttprequest','websocket']}}))];
}
function validObservedEvent(input){
 return ['navigation','prompt','response'].includes(input?.kind)&&
  ['observed','blocked','redirected'].includes(input.action)&&
  Number.isInteger(input.characters)&&input.characters>=0&&input.characters<=32768;
}
function observedFileNames(input,collection){
 if(input.kind!=='prompt'||!collection.store_file_names||!Array.isArray(input.files)){return [];}
 return input.files.filter(name=>typeof name==='string'&&name.length>0&&name.length<=200&&![...name].some(c=>c.codePointAt(0)<32||c.codePointAt(0)===127)).slice(0,20);
}
 // `sender.url` is the URL the document was COMMITTED at, and none of these providers
 // reloads when the conversation changes: measured on claude.ai 2026-09-15, the worker
 // still read `/new` while the tab was on `/chat/<uuid>`. Every event of that tab then
 // carried the identifier of the first conversation it ever showed -- or none at all --
 // so distinct conversations became one. The document reports its live `location.href`;
 // it is honoured only while it names the same provider the frame is trusted for, so a
 // compromised page can still only speak about its own domain.
function eventContext(input,senderUrl,policy){
 const frame=globalThis.MilvagoAdapters.context(senderUrl);
 if(!frame){return null;}
 const live=typeof input?.url==='string'?globalThis.MilvagoAdapters.context(input.url):null;
 const context=live&&live.provider===frame.provider?live:frame;
 return policy.config.services.some(s=>s.enabled&&s.domains.includes(context.provider))?context:null;
}
export function eventForPolicy(input,senderUrl,tool,policy){
 if(!validPolicy(policy)||![2,3].includes(policy.version)||!policy.config.collection.enabled){return null;}
 const context=eventContext(input,senderUrl,policy);
 if(!context){return null;}
 if(!validObservedEvent(input)){return null;}
 const event={...context,source:'browser',tool,kind:input.kind,action:input.action,characters:input.kind==='navigation'?0:input.characters,labels:Array.isArray(input.labels)?input.labels.filter(s=>typeof s==='string'&&/^[a-z0-9_-]{1,64}$/i.test(s)).slice(0,32):[],policy_revision:policy.revision};
 if(typeof input.correlation_id==='string'&&/^[a-zA-Z0-9_-]{1,200}$/.test(input.correlation_id)){event.correlation_id=input.correlation_id;}
 // No model here on purpose: it is never supplied by the document. It is read from the
 // outgoing request by the service worker and attached there, so a compromised page
 // cannot name the model its own traffic is attributed to.
 let body=null;if(input.kind==='prompt'){body='prompt';}else if(input.kind==='response'){body='response';}
 if(body&&policy.config.collection.store_content&&typeof input[body]==='string'&&new TextEncoder().encode(input[body]).length<=32768){event[body]=input[body];}
 // Names of attached files, never their contents, and only while the policy asks
 // for them. A page cannot widen this: the switch comes from the signed policy.
 const files=observedFileNames(input,policy.config.collection);
 if(files.length){event.files=files;}
 return event;
}
