// Independent DOM adapters. Provider UI changes can require selector updates.
(() => {
 const catalog = [
  // chatgpt.com serves TWO apps: the desktop one, and the one you get in a
  // logged-out session or narrow window (`/unauth-mweb/…` routes). Measured on
  // 2026-09-15 with the composer filled in: its field is `textarea#mobile-composer-prompt` and its
  // send control is the only `type="submit"` in its form — its classes are generated
  // and unreadable. The form is identified by the field's id so this
  // branch cannot match another send button on the desktop page.
  ['chatgpt','chatgpt.com','#prompt-textarea,textarea[data-testid="prompt-textarea"],#mobile-composer-prompt','button[data-testid="send-button"],form:has(#mobile-composer-prompt) button[type="submit"]','[data-message-author-role="assistant"]',/^\/c\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // Measured on the page on 2026-09-14: `data-testid="chat-input-send"` matches a
  // single button, composer filled in, and closes the Spanish / Brazilian Portuguese gap.
  // Assets host MEASURED on 2026-09-16 by replaying a network capture of claude.ai: 60 of the
  // 61 sealed requests targeted `assets-proxy.anthropic.com` — 54 scripts, 3 style
  // sheets, 3 fonts. It is a registrable domain DIFFERENT from `claude.ai`, so the
  // subdomain rule does not reach it: without this entry the page cannot
  // render under content control. The host is allowed to be LOADED, that does not
  // make it covered. Second host measured the same day in the qualification
  // profile, extension 0.5.30: `s-cdn.anthropic.com` serves a page script
  // (`/s.js`), also sealed until it was named.
  ['claude','claude.ai','[contenteditable="true"][role="textbox"],.ProseMirror[contenteditable="true"]','button[data-testid="chat-input-send"]','[data-is-streaming],[data-testid="assistant-message"]',/^\/chat\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/,undefined,['assets-proxy.anthropic.com','s-cdn.anthropic.com']],
  // Two `button[type="submit"]` coexist on the page; only the composer's carries
  // `aria-busy`. Disambiguation by attribute, never by position.
  ['lechat','chat.mistral.ai','textarea,[contenteditable="true"]','button[type="submit"][aria-busy]','[data-message-role="assistant"]',/^\/chat\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // `[data-testid="assistant-message"]` matched nothing: the two attributes
  // live on the same node. A dead branch in a comma-separated list does not just
  // find nothing, it hides that the measurement was never actually done.
  ['copilot','copilot.microsoft.com','textarea,[contenteditable="true"][role="textbox"]','button[data-testid="submit-button"],button[aria-label="Submit message"]','[data-content="ai-message"]',/^\/chats\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // `send-button` is the class of the wrapper element, not of the button inside it,
  // and the other branch was an English aria-label: this selector matched nothing at
  // all on a French interface, so Gemini reported neither prompt nor response since
  // the beginning. Measured on the page 2026-09-14: `.send-button button` matches
  // exactly one element, whatever the interface language.
  ['gemini','gemini.google.com','rich-textarea [contenteditable="true"],textarea','.send-button button','model-response',/^\/app\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // Google serves `notebook.google.com`; the old domain becomes the alias. The
  // Send/Envoyer labels matched TWO buttons, `type="submit"` matches only one.
  ['notebooklm','notebook.google.com','textarea,[contenteditable="true"][role="textbox"]','button[type="submit"]','[data-message-role="assistant"],.to-user-message',/^\/notebook\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // DeepSeek exposes no <button> around its composer: its send control is a
  // `div[role="button"]` from its in-house component library. No `button[…]` selector will
  // ever match; `submissionTarget()` accommodates this, with no form.
  ['deepseek','chat.deepseek.com','textarea','div[role="button"].ds-button--primary.ds-button--circle','[data-message-role="assistant"]',/^\/a\/chat\/s\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
  // Perplexity has NO structural hook at all: no test id, no type="submit",
  // no stable class — only a label, and its interface language follows the browser
  // across dozens of languages. The three fields are neutralized TOGETHER: keeping
  // `editor` with an empty `send` would intercept the Enter key and then fail the
  // resubmission, which blocks the person's send. Observation by network only.
  // Seventh field: the canonical path of a conversation, for when it cannot be
  // the one that was recognized. Perplexity's URL carries a summary of the question before
  // the id, variable and irrelevant, and `/search/<id>` refers to the same page.
  ['perplexity','www.perplexity.ai',':not(*)',':not(*)',':not(*)',/^\/search\/(?:[a-z0-9_-]*-)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$)/i,id=>`/search/${id}`],
  ['grok','grok.com','textarea,[contenteditable="true"][role="textbox"]','button[data-testid="chat-submit"]','[data-message-role="assistant"],[data-testid="assistant-message"]',/^\/c\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
 ];
 // Eighth field, optional: the assets hosts this provider's page is allowed
 // to fetch from in addition to its domain and its subdomains. It does NOT make the host
 // "covered" — no content script, no event attribution — it only says
 // that the page may load it under content control. Each entry must be MEASURED
 // on the site, never assumed: it is an allow list, it is never filled in
 // from memory. Empty until the measurement has been done.
 const adapters=catalog.map(([id,domain,editor,send,response,conversation,path,assets])=>({id,domain,editor,send,response,conversation,path,assets:Array.isArray(assets)?assets:[]}));
 // A provider that renames its domain keeps the old one as an alias of the new: the
 // lookup therefore goes from the encountered name to the one the catalog names first.
 const aliases={'chat.openai.com':'chatgpt.com','copilot.cloud.microsoft':'copilot.microsoft.com','perplexity.ai':'www.perplexity.ai','notebooklm.google.com':'notebook.google.com'};
 // `claude.ai.` and `claude.ai` are the same host for DNS and TLS, but `URL` keeps the trailing
 // dot: without this canonical form, `api.anthropic.com.` escaped the network guard entirely.
 function resolve(value){try{const u=new URL(value);let end=u.hostname.length;while(end>0&&u.hostname[end-1]==='.'){end--;}const host=u.hostname.slice(0,end),adapter=adapters.find(a=>a.domain===(aliases[host]||host));return u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&adapter?{...adapter,domain:host}:null;}catch{return null;}}
 function context(value){const adapter=resolve(value);if(!adapter){return null;}const u=new URL(value),match=u.pathname.match(adapter.conversation);const result={provider:adapter.domain,url:u.origin};if(match){result.conversation_id=match[1];result.url+=adapter.path?adapter.path(match[1]):match[0].replaceAll(/\/$/g,'');}return result;}
 function read(editor){if('value' in editor){return editor.value;}if(typeof editor.innerText==='string'){return editor.innerText;}return editor.textContent||'';}
 // The model is deliberately NOT read from the page. Measured on the real sites on
 // 2026-09-14: claude.ai shows a localized composite ("Fable 5.1 Moyen" — model and
 // effort fused, translated), and chatgpt.com exposes no identifiable control at all.
 // The outgoing request carries the canonical identifier, the effort in its own
 // field, and — on ChatGPT — the conversation identifier; that is the source of
 // truth. See the network rules of the detection catalog.
 // Returns the text READ BACK from the editor, or `null`. A rich editor (ProseMirror on
 // claude.ai) puts each line in its own paragraph: `innerText` then renders `\n\n` between
 // two lines, a trailing break or a non-breaking space, and byte-for-byte equality failed for
 // any masked prompt spanning more than one line. Only these formatting differences are tolerated;
 // the caller submits the text read back, which the agent inspects again.
 const layout=value=>value.replaceAll(/\r\n?/g,'\n').replaceAll(' ',' ').replaceAll(/\n+/g,'\n').trim();
 function write(editor,text){
  const doc=editor.ownerDocument,win=doc.defaultView;
  if('value' in editor){const prototype=editor.tagName==='TEXTAREA'?win.HTMLTextAreaElement.prototype:win.HTMLInputElement.prototype;const setter=Object.getOwnPropertyDescriptor(prototype,'value')?.set;if(setter){setter.call(editor,text);}else {editor.value=text;}}
  else if(typeof doc.execCommand==='function'){
   editor.focus();const range=doc.createRange();range.selectNodeContents(editor);const selection=win.getSelection();selection.removeAllRanges();selection.addRange(range);
   // Native editing notifies stateful editors and preserves line breaks/undo.
   // A provider refusal leaves the draft untouched and the caller stops.
   if(!doc.execCommand('insertText',false,text)){return null;}
  }else {editor.textContent=text;}
  editor.dispatchEvent(new win.Event('input',{bubbles:true}));const applied=read(editor);return layout(applied)===layout(text)?applied:null;
 }
 function submissionTarget(adapter,event,editor,document){
  const clicked=event.type==='click'?event.target?.closest?.(adapter.send):null;
  const form=clicked?.form||editor.closest('form');
  let control=clicked||form?.querySelector(adapter.send);
  // With no form and no click, resubmission relies on this fallback. What must be unique is
  // the BUTTON, not the editor: `editor` is already the one that received the trusted keystroke,
  // returned by `submission()` from the event target, so requiring that no other
  // element match the editor selector would rule out no real ambiguity.
  // Measured on 2026-09-14: gemini, copilot, notebooklm and grok expose TWO elements for
  // their editor selector and have no form — Enter was therefore
  // intercepted then dropped there, blocking the person's send, whether or not the send button was live.
  if(!control){const controls=[...document.querySelectorAll(adapter.send)];if(controls.length===1&&editor.matches(adapter.editor)){control=controls[0];}}
  if(control&&(!control.isConnected||control.disabled||control.getAttribute('aria-disabled')==='true')){return null;}
  if(control){return {control,form:control.form||form,target:control};}if(form&&typeof form.requestSubmit==='function'){return {control:null,form,target:form};}return null;
 }
 function responseBusy(adapter,node,document){
  return !!node.closest('[data-is-streaming="true"],[aria-busy="true"]')||!!node.querySelector('[data-is-streaming="true"],[aria-busy="true"]')||!!document.querySelector('button[data-testid="stop-button"],button[aria-label="Stop generating"],button[aria-label="Stop response"],button[aria-label="Arrêter la génération"]');
 }
 // `allowEmpty`: a file from this draft has already been checked and recorded. Sending it with no
 // text must then still go through the check like any other, otherwise it leaves without approval and
 // the network guard seals it under masking.
 function submission(adapter,event,document,allowEmpty=false){
  if(!event.isTrusted||event.isComposing||event.defaultPrevented){return null;}const target=event.target;if(!target?.closest){return null;}
  if(event.type==='keydown'&&(event.key!=='Enter'||event.shiftKey||event.ctrlKey||event.altKey||event.metaKey||!target.matches(adapter.editor))){return null;}
  if(event.type==='click'&&!target.closest(adapter.send)){return null;}
  if(event.type==='submit'&&target.tagName!=='FORM'){return null;}
  const scope=event.type==='submit'?target:target.closest('form');const editor=(event.type==='keydown'?target:scope?.querySelector(adapter.editor))||document.querySelector(adapter.editor);
  return editor&&(read(editor).trim()||allowEmpty)?editor:null;
 }

 // Shape of a receipt/delivery id (UUID v1-5, variant 8/9/a/b). Duplicated
 // identically (verified) in six places: capture.js and background.js read it
 // from here. detection.js and detection-runtime.js keep their own literal: some
 // tests there replace globalThis.MilvagoAdapters with a partial stub (without this
 // key) on code paths that would otherwise reach it, which would make them fail.
 const RECEIPT_ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-58][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

 const factoryAdapters=adapters.map(a=>({...a})),factoryAliases={...aliases};
 function applyCatalog(content){
  adapters.splice(0,adapters.length,...factoryAdapters.map(a=>({...a})));for(const k of Object.keys(aliases)){delete aliases[k];}Object.assign(aliases,factoryAliases);
  if(!content){return;}
  const next=content.providers.map(p=>{
   // `conversation_paths` adds page shapes of the same thread, same segment: signed-out
   // ChatGPT moves to `/uc/<id>` where an account uses `/c/<id>`.
   const patterns=[p.conversation_path,...(Array.isArray(p.conversation_paths)?p.conversation_paths:[])].filter(v=>typeof v==='string'&&v).map(v=>v.split('/').filter(Boolean));
   // The canonical path is derived from the pattern that recognized the page: its literal
   // segments, the id in its place. Recognized and canonical differ wherever the URL
   // carries a summary of the question.
   const canonical=(pattern,id)=>'/'+pattern.map((v,i)=>i===p.conversation_segment?id:v).join('/');
   const match=path=>{const pieces=path.split('/').filter(Boolean);for(const pattern of patterns){if(pattern.length!==pieces.length||!pattern.every((v,i)=>v==='*'||v===pieces[i])){continue;}const id=pieces[p.conversation_segment];if(/^[A-Za-z0-9_-]{8,128}$/.test(id||'')){return [canonical(pattern,id),id];}}return null;};
   const path=null;
   // Assets hosts are the UNION of the same provider's factory list and what the
   // served catalog names (`asset_hosts`). Measured on 2026-09-16 in a live 0.5.29 worker:
   // the served catalog (revision 9) did not carry `asset_hosts`, so this reconstruction produced
   // `assets: []` and discarded the factory measurement — 60 requests to `assets-proxy.anthropic.com`
   // sealed in the browser, when replaying without a served catalog sealed none of them. The
   // factory list ships inside the signed extension: keeping it as a floor opens nothing that
   // was not measured, and a served catalog can only ADD a host to it, itself measured in turn.
   const factory=factoryAdapters.find(a=>a.id===p.id)?.assets||[];
   const named=Array.isArray(p.asset_hosts)?p.asset_hosts.filter(h=>typeof h==='string'):[];
   return {id:p.id,domain:p.domains[0],editor:p.dom.editor||':not(*)',send:p.dom.send||':not(*)',response:p.dom.response||':not(*)',conversation:{test:path=>!!match(path),[Symbol.match]:match},path,assets:[...new Set([...factory,...named])]};
  });
  adapters.splice(0,adapters.length,...next);for(const k of Object.keys(aliases)){delete aliases[k];}
  for(const p of content.providers){for(const d of [...p.domains.slice(1),...(p.aliases||[])]){aliases[d]=p.domains[0];}}
 }

 globalThis.MilvagoAdapters={adapters,aliases,resolve,context,read,write,submission,submissionTarget,responseBusy,applyCatalog,RECEIPT_ID};
})();
