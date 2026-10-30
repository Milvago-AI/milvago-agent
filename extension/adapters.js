// Independent DOM adapters. Provider UI changes can require selector updates.
(() => {
 const catalog = [
  // chatgpt.com serves TWO apps: the desktop one, and the one you get in a
  // logged-out session or narrow window (`/unauth-mweb/…` routes). Measured on
  // 2026-09-15 with the composer filled in: its field is `textarea#mobile-composer-prompt` and its
  // send control is the only `type="submit"` in its form — its classes are generated
  // and unreadable. The form is identified by the field's id so this
  // branch cannot match another send button on the desktop page.
  // The desktop send (ProseMirror composer, measured by CDP 2026-10-16) has neither test id nor id:
  // it is the `type="submit"` inside the composer body, never another submit of the form.
  // Signed in, answers lost `data-message-author-role`: their text sits in
  // `[data-markdown-text-style="assistant-message"]` (measured 2026-10-16). The old marks stay as fallbacks.
  ['chatgpt','chatgpt.com','#prompt-textarea,textarea[data-testid="prompt-textarea"],#mobile-composer-prompt,.ProseMirror[data-composer-markdown]','button[data-testid="send-button"],form:has(#mobile-composer-prompt) button[type="submit"],[data-composer-body]:has(.ProseMirror[data-composer-markdown]) button[type="submit"]','[data-markdown-text-style="assistant-message"],[data-message-author-role="assistant"],[data-message-role="assistant"]',/^\/u?c\/([a-zA-Z0-9_-]{8,128})(?:\/|$)/],
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
 ];
 // Eighth field, optional: the assets hosts this provider's page is allowed
 // to fetch from in addition to its domain and its subdomains. It does NOT make the host
 // "covered" — no content script, no event attribution — it only says
 // that the page may load it under content control. Each entry must be MEASURED
 // on the site, never assumed: it is an allow list, it is never filled in
 // from memory. Empty until the measurement has been done.
 // Ninth field, optional: third-party endpoints the page posts its draft to while the person types
 // (`{host,path,field}`, measured), guarded like a draft sub-route of the send (`detection.js`).
 const adapters=catalog.map(([id,domain,editor,send,response,conversation,path,assets,drafts])=>({id,domain,editor,send,response,conversation,path,assets:Array.isArray(assets)?assets:[],drafts:Array.isArray(drafts)?drafts:[]}));
 // A provider that renames its domain keeps the old one as an alias of the new: the
 // lookup therefore goes from the encountered name to the one the catalog names first.
 const aliases={'chat.openai.com':'chatgpt.com'};
 // `claude.ai.` and `claude.ai` are the same host for DNS and TLS, but `URL` keeps the trailing
 // dot: without this canonical form, `api.anthropic.com.` escaped the network guard entirely.
 function resolve(value){try{const u=new URL(value);let end=u.hostname.length;while(end>0&&u.hostname[end-1]==='.'){end--;}const host=u.hostname.slice(0,end),adapter=adapters.find(a=>a.domain===(aliases[host]||host));return u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&adapter?{...adapter,domain:host}:null;}catch{return null;}}
 function context(value){const adapter=resolve(value);if(!adapter){return null;}const u=new URL(value),match=u.pathname.match(adapter.conversation);const result={provider:adapter.domain,url:'https://'+adapter.domain};if(match){result.conversation_id=match[1];result.url+=adapter.path?adapter.path(match[1]):match[0].replaceAll(/\/$/g,'');}return result;}
 // `value` only when it is text: an `<li>` has a numeric `value` (its list ordinal), and
 // signed-out ChatGPT answers are `li[data-message-role="assistant"]` (measured 2026-09-29).
 // Zero-width characters an editor adds to its draft (U+200B, U+200C, measured 2026-10-16)
 // are not text the person typed: kept, they failed the read-back of a masked draft and were counted.
 // The joiner U+200D stays, it belongs to emoji sequences. The agent drops all of them before inspection.
 const ZERO_WIDTH=/[​‌⁠﻿]/g;
 function read(editor){return (typeof editor.value==='string'?editor.value:typeof editor.innerText==='string'?editor.innerText:editor.textContent||'').replaceAll(ZERO_WIDTH,'');}
 // An answer's text without the relative time it shows: claude.ai puts "il y a 35 minutes" in a `<time>`
 // inside the answer (measured 2026-10-16), and the text changing every minute delivered it again.
 // A screen-reader heading the page puts first in the answer (claude.ai: "Claude a répondu : …", measured
 // 2026-10-16, Tailwind `sr-only`) is not the answer either, in any interface language.
 // Nor are, measured on the real pages 2026-10-17: the Angular CDK's screen-reader label, a reasoning block
 // shown above the answer ("Réflexion : 3s", "Thoughts"), an icon drawn by a font ligature ("expand_more") or
 // by a private-use glyph (claude.ai's action bar, U+E056…). A reasoning block alone is no answer yet: the
 // empty text waits for the answer itself.
 const NOT_ANSWER='.sr-only,.visually-hidden,.cdk-visually-hidden,.thinking-container,.thinking-chain,mat-icon,.material-icons,.material-symbols-outlined,.google-symbols';
 const PRIVATE_USE=new RegExp('['+String.fromCharCode(0xE000)+'-'+String.fromCharCode(0xF8FF)+']','g');
 // A heading clipped out of view is a screen-reader label whatever its class names: signed-out ChatGPT's
 // "ChatGPT a dit :" is an `h4` with atomic classes (absolute, 1px, `clip-path: inset(50%)`, measured 2026-10-17).
 // Hiding an answer this way only loses its capture: this text is never what a control decides on.
 const HEADING='h1,h2,h3,h4,h5,h6,[role="heading"]';
 const CLIPPED=/^rect\(\s*0(?:px)?(?:[,\s]+0(?:px)?){3}\s*\)$/;
 function clipped(el){const s=el.ownerDocument?.defaultView?.getComputedStyle?.(el);return !!s&&(s.clipPath==='inset(50%)'||CLIPPED.test(s.clip||'')||s.position==='absolute'&&Number.parseFloat(s.width)<=1&&Number.parseFloat(s.height)<=1);}
 function answer(node){
  let text=read(node),from=0;
  const parts=[...(node.querySelectorAll?.(NOT_ANSWER+','+HEADING)||[])].filter(el=>el.matches(NOT_ANSWER)||clipped(el));
  // In page order, each from where the last one was cut: a short label ("1") is never cut out of the answer before it.
  for(const label of parts.filter(p=>!parts.some(o=>o!==p&&o.contains(p))).map(read)){const at=label?text.indexOf(label,from):-1;if(at>=0){text=text.slice(0,at)+text.slice(at+label.length);from=at;}}
  text=text.replace(PRIVATE_USE,'');
  for(const time of [...(node.querySelectorAll?.('time')||[])].reverse()){const label=read(time),at=label?text.lastIndexOf(label):-1;if(at>=0){text=text.slice(0,at)+text.slice(at+label.length);}}
  return text.trim();
 }
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
 const layout=value=>value.replaceAll(ZERO_WIDTH,'').replaceAll(/\r\n?/g,'\n').replaceAll(' ',' ').replaceAll(/\n+/g,'\n').trim();
 // A Lexical editor (measured by CDP 2026-10-16) edits the selection it read on `selectionchange`,
 // which the browser fires after the call that moved it: inserting at once replaced nothing. It also
 // drops the line breaks of `insertText`; a plain-text paste keeps them, so it is the second try.
 const settle=(win,event)=>new Promise(resolve=>{const doc=win.document,done=()=>{win.clearTimeout(timer);if(event){doc.removeEventListener(event,done);}win.setTimeout(resolve,0);},timer=win.setTimeout(done,event?200:50);if(event){doc.addEventListener(event,done,{once:true});}});
 function applied(editor,text){const value=read(editor);return layout(value)===layout(text)?value:null;}
 async function write(editor,text){
  const doc=editor.ownerDocument,win=doc.defaultView;
  if('value' in editor){const prototype=editor.tagName==='TEXTAREA'?win.HTMLTextAreaElement.prototype:win.HTMLInputElement.prototype;const setter=Object.getOwnPropertyDescriptor(prototype,'value')?.set;if(setter){setter.call(editor,text);}else {editor.value=text;}}
  else if(typeof doc.execCommand==='function'){
   const selectAll=async()=>{editor.focus();const range=doc.createRange();range.selectNodeContents(editor);const selection=win.getSelection();selection.removeAllRanges();selection.addRange(range);await settle(win,'selectionchange');};
   await selectAll();
   // Native editing notifies stateful editors and preserves line breaks/undo.
   // A provider refusal leaves the draft untouched and the caller stops.
   if(!doc.execCommand('insertText',false,text)){return null;}
   editor.dispatchEvent(new win.Event('input',{bubbles:true}));
   if(applied(editor,text)!==null){return applied(editor,text);}
   await settle(win);
   if(applied(editor,text)!==null||typeof win.DataTransfer!=='function'||typeof win.ClipboardEvent!=='function'){return applied(editor,text);}
   await selectAll();const data=new win.DataTransfer();data.setData('text/plain',text);
   editor.dispatchEvent(new win.ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true}));
   await settle(win);return applied(editor,text);
  }else {editor.textContent=text;}
  editor.dispatchEvent(new win.Event('input',{bubbles:true}));return applied(editor,text);
 }
 // Puts inspected pasted text where the paste was aimed. A field takes it as typed text: no paste
 // handler of the page runs, so a long text stays text rather than becoming an upload. A rich
 // editor gets a synthetic plain-text paste, which framework editors read (line breaks kept, a long
 // text may become a chip); one that ignores it (Quill, measured) gets `insertText`. Never the
 // original HTML. Returns false when nothing could be inserted.
 async function insert(target,text,range){
  const doc=target.ownerDocument,win=doc.defaultView,field=target.closest?.('textarea,input')||null;
  (field||target.closest?.('[contenteditable]')||target).focus?.();
  if(field){
   if(typeof doc.execCommand==='function'&&doc.execCommand('insertText',false,text)){return true;}
   try{field.setRangeText(text,field.selectionStart??field.value.length,field.selectionEnd??field.value.length,'end');}catch{return false;}
   field.dispatchEvent(new win.Event('input',{bubbles:true}));return true;
  }
  if(range?.startContainer?.isConnected){const selection=win.getSelection();selection.removeAllRanges();selection.addRange(range);await settle(win,'selectionchange');}
  if(typeof win.DataTransfer==='function'&&typeof win.ClipboardEvent==='function'){
   const data=new win.DataTransfer();data.setData('text/plain',text);
   if(!target.dispatchEvent(new win.ClipboardEvent('paste',{clipboardData:data,bubbles:true,cancelable:true}))){return true;}
   // An editor that let the paste go still flattens line breaks typed in the same task (measured 2026-10-17).
   await settle(win);
  }
  return typeof doc.execCommand==='function'&&doc.execCommand('insertText',false,text);
 }
 function submissionTarget(adapter,event,editor,document){
  const clicked=event.type==='click'?event.target?.closest?.(adapter.send):null;
  const form=clicked?.form||editor.closest('form');
  let control=clicked||form?.querySelector(adapter.send);
  // With no form and no click, resubmission relies on this fallback. What must be unique is
  // the BUTTON, not the editor: `editor` is already the one that received the trusted keystroke,
  // returned by `submission()` from the event target, so requiring that no other
  // element match the editor selector would rule out no real ambiguity.
  // Measured on 2026-09-14: several providers expose TWO elements for
  // their editor selector and have no form — Enter was therefore
  // intercepted then dropped there, blocking the person's send, whether or not the send button was live.
  if(!control){const controls=[...document.querySelectorAll(adapter.send)];if(controls.length===1&&editor.matches(adapter.editor)){control=controls[0];}}
  // A control disabled at this instant is still the target: the caller waits briefly for the
  // page to enable it (a button greyed while the page validates the draft) before giving up.
  if(control&&!control.isConnected){return null;}
  if(control){return {control,form:control.form||form,target:control};}if(form&&typeof form.requestSubmit==='function'){return {control:null,form,target:form};}
  // Enter with neither a recognized button nor a form: the approved send is replayed as the same
  // key on the editor, so a provider whose button cannot be named is not blocked at every Enter.
  if(event.type==='keydown'){return {control:null,form:null,target:editor,key:true};}
  return null;
 }
 // A field that is not rendered (`hidden`, `inert`, `aria-hidden`, `display:none`,
 // `visibility:hidden`) is never what the person typed in.
 function shown(node){
  if(!node.isConnected||node.closest('[hidden],[inert],[aria-hidden="true"]')){return false;}
  const style=node.ownerDocument.defaultView?.getComputedStyle?.(node);
  if(style&&(style.display==='none'||style.visibility==='hidden')){return false;}
  return typeof node.checkVisibility!=='function'||node.checkVisibility({visibilityProperty:true});
 }
 // The editor a click or a submit sends: the visible one holding text in the clicked form, or else
 // in the nearest ancestor of the target that holds a visible editor. A provider may keep a
 // hidden `textarea` worth "x" beside its real composer: reading the first match inspected one
 // character while the real text left unchecked. With no visible
 // text, ONE filled hidden field is returned so that it is inspected and approved like any send
 // (a file sent alone beside that hidden "x"). `false` refuses the send: two visible drafts, or
 // text in several hidden fields, leave no editor that can be trusted.
 function composer(adapter,target,scope,document,allowEmpty){
  let region=scope?.querySelector(adapter.editor)?scope:null;
  for(let node=target.parentElement;!region&&node;node=node.parentElement){if([...node.querySelectorAll(adapter.editor)].some(shown)){region=node;}}
  // A field nested in another matching one is the same composer, counted once.
  const all=[...(region||document).querySelectorAll(adapter.editor)],shownAll=all.filter(shown),visible=shownAll.filter(e=>!shownAll.some(o=>o!==e&&o.contains(e))),filled=visible.filter(e=>read(e).trim());
  const hiddenAll=all.filter(e=>!shownAll.includes(e)&&read(e).trim()),hidden=hiddenAll.filter(e=>!hiddenAll.some(o=>o!==e&&o.contains(e)));
  if(filled.length>1||(!filled.length&&hidden.length>1)){return false;}
  return filled[0]||hidden[0]||(allowEmpty&&visible[0])||null;
 }
 function responseBusy(adapter,node,document){
  // `data-message-streaming`: signed-out ChatGPT marks the answer being generated with it
  // (measured 2026-09-29), whatever the interface language the stop label is in. claude.ai's stop button,
  // `chat-input-stop`, is labelled in that language too ("Arrêter la réponse", real campaign 0.7.10).
  return !!node.closest('[data-is-streaming="true"],[aria-busy="true"],[data-message-streaming]')||!!node.querySelector('[data-is-streaming="true"],[aria-busy="true"],[data-message-streaming]')||!!document.querySelector('button[data-testid="stop-button"],button[data-testid="chat-input-stop"],button[aria-label="Stop generating"],button[aria-label="Stop response"],button[aria-label="Arrêter la génération"]');
 }
 // `allowEmpty`: a file from this draft has already been checked and recorded. Sending it with no
 // text must then still go through the check like any other, otherwise it leaves without approval and
 // the network guard seals it under masking.
 function submission(adapter,event,document,allowEmpty=false){
  if(!event.isTrusted||event.isComposing||event.defaultPrevented){return null;}const target=event.target;if(!target?.closest){return null;}
  if(event.type==='keydown'&&(event.key!=='Enter'||event.shiftKey||event.ctrlKey||event.altKey||event.metaKey||!target.matches(adapter.editor))){return null;}
  if(event.type==='click'&&!target.closest(adapter.send)){return null;}
  if(event.type==='submit'&&target.tagName!=='FORM'){return null;}
  if(event.type==='keydown'){return read(target).trim()||allowEmpty?target:null;}
  // `false`: a send whose editor cannot be resolved, which the caller refuses with a notice.
  return composer(adapter,target,event.type==='submit'?target:target.closest('form'),document,allowEmpty);
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
   return {id:p.id,domain:p.domains[0],editor:p.dom.editor||':not(*)',send:p.dom.send||':not(*)',response:p.dom.response||':not(*)',conversation:{test:path=>!!match(path),[Symbol.match]:match},path,assets:[...new Set([...factory,...named])],drafts:factoryAdapters.find(a=>a.id===p.id)?.drafts||[]};
  });
  adapters.splice(0,adapters.length,...next);for(const k of Object.keys(aliases)){delete aliases[k];}
  for(const p of content.providers){for(const d of [...p.domains.slice(1),...(p.aliases||[])]){aliases[d]=p.domains[0];}}
 }

 globalThis.MilvagoAdapters={adapters,aliases,resolve,context,read,answer,write,insert,layout,submission,submissionTarget,responseBusy,applyCatalog,RECEIPT_ID};
})();
