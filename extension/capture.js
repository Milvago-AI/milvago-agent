(() => {
 const A=globalThis.MilvagoAdapters,api=globalThis.browser||globalThis.chrome;
 const encoder=new TextEncoder();
 function stop(event){event.preventDefault();event.stopImmediatePropagation();}
 function sameFiles(list,files){return list?.length===files.length&&files.every((file,index)=>list[index]===file);}
 const COMMUNITY_SIGNATURE='';
 const TEXT=[["Envoi en attente","Send pending","Envío pendiente","Envio pendente"],["Fichier en attente","File pending","Archivo pendiente","Arquivo pendente"],["Envoi bloqué","Send blocked","Envío bloqueado","Envio bloqueado"],["Redirection refusée","Redirect refused","Redirección rechazada","Redirecionamento recusado"],["Service autorisé","Allowed service","Servicio autorizado","Serviço permitido"],["Informations confidentielles","Confidential information","Información confidencial","Informações confidenciais"],["Valider et envoyer","Confirm and send","Confirmar y enviar","Confirmar e enviar"],["Utiliser ce texte","Use this text","Usar este texto","Usar este texto"],["Annuler","Cancel","Cancelar","Cancelar"],["Fermer","Close","Cerrar","Fechar"],["Ouvrir le service","Open service","Abrir el servicio","Abrir o serviço"],["Milvago — contrôle local","Milvago — local inspection","Milvago — control local","Milvago — verificação local"],["Texte contrôlé à envoyer","Inspected text to send","Texto revisado para enviar","Texto verificado para enviar"],["Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.","The information you provided contains confidential information. Please review the elements we masked below before sending.","La información que has proporcionado contiene información confidencial. Revisa los elementos que hemos enmascarado a continuación antes de enviar.","As informações que você forneceu contêm informações confidenciais. Verifique os elementos que mascaramos abaixo antes de enviar."],["Ce contrôle ne permet pas de reprendre automatiquement l’envoi.","This control cannot resume sending automatically.","Este control no permite reanudar el envío automáticamente.","Este controle não permite retomar o envio automaticamente."],["Le texte dépasse la limite du contrôle local (32 Kio). Réduisez-le avant de réessayer.","The text exceeds the local inspection limit (32 KiB). Shorten it before retrying.","El texto supera el límite del control local (32 KiB). Redúcelo antes de volver a intentarlo.","O texto excede o limite da verificação local (32 KiB). Reduza-o antes de tentar novamente."],["Connectez l’agent local puis réessayez.","Connect the local agent and retry.","Conecta el agente local y vuelve a intentarlo.","Conecte o agente local e tente novamente."],["Réponse de contrôle non valide.","Invalid inspection response.","Respuesta de control no válida.","Resposta de verificação inválida."],["Le lien avec le reçu durable est indisponible.","The durable receipt link is unavailable.","El vínculo con el recibo persistente no está disponible.","O vínculo com o recibo persistente está indisponível."],["La validation finale ou l’enregistrement durable a échoué.","Final validation or durable recording failed.","La validación final o el registro persistente falló.","A validação final ou o registro persistente falhou."],["La validation finale a échoué.","Final validation failed.","La validación final falló.","A validação final falhou."],["La politique locale bloque cet envoi.","The local policy blocks this send.","La política local bloquea este envío.","A política local bloqueia este envio."],["La destination de la politique est invalide.","The policy destination is invalid.","El destino de la política no es válido.","O destino da política é inválido."],["Le texte contrôlé n’a pas pu être appliqué au brouillon.","The inspected text could not be applied to the draft.","No se pudo aplicar el texto revisado al borrador.","Não foi possível aplicar o texto verificado ao rascunho."],["Ce navigateur ne permet pas de reprendre ce transfert. Utilisez le sélecteur de fichiers.","This browser cannot resume this transfer. Use the file picker.","Este navegador no permite reanudar esta transferencia. Usa el selector de archivos.","Este navegador não permite retomar esta transferência. Use o seletor de arquivos."],["La sélection de fichiers a changé.","The file selection changed.","La selección de archivos cambió.","A seleção de arquivos mudou."],["Le contrôle local refuse ce transfert.","Local inspection refuses this transfer.","El control local rechaza esta transferencia.","A verificação local recusa esta transferência."],["L’agent local ne répond pas.","The local agent is not responding.","El agente local no responde.","O agente local não responde."],["La validation a expiré. Réessayez.","Validation expired. Retry.","La validación caducó. Vuelve a intentarlo.","A validação expirou. Tente novamente."],
 // Edition signature. The key is the French string, the one `build-editions.js`
 // injects into `COMMUNITY_SIGNATURE` for the Community edition only: `t()` then
 // translates it like any other label, so a language added to the table
 // covers it without touching the build script.
 ["Sécurisé par Milvago Community","Secured by Milvago Community","Protegido por Milvago Community","Protegido pelo Milvago Community"]];

 function start(document,location,send){
  const adapter=A.resolve(location.href);if(!adapter){return null;}
  const win=document.defaultView;
  const language=()=>{const value=(document.documentElement.lang||win.navigator.language||'fr').toLowerCase();if(value.startsWith('en')){return 1;}if(value.startsWith('es')){return 2;}if(value.startsWith('pt')){return 3;}return 0;};
  const t=value=>TEXT.find(row=>row[0]===value)?.[language()]||value;
  let policy,overlay,pending=false,correlation,lastUrl='',replay,disposed=false,draftEpoch=0,attempt=0;
  // The correlation of the exchange **currently being composed**. A file goes to the
  // provider as soon as it is attached, so it is recorded at that moment, before
  // the text is sent: without this key, its event only carried the correlation of
  // the PREVIOUS exchange, or none at all on the first message of a discussion — it
  // would then appear as a conversation on its own. The text that follows reuses
  // this correlation, which reunites the attachment with the send it accompanies.
  let draftCorrelation=null;
  // Names of the files attached to the request being composed. Names only: the
  // contents are never read. They are collected where a file actually enters a
  // composer — a picker selection, a drop, a paste — rather than by guessing at
  // each site's markup, so no interface change can silently stop this working.
  // A file added through a path the page never exposes stays invisible.
  const receipts=[];
  const validReceipt=value=>typeof value==='string'&&A.RECEIPT_ID.test(value);
  function receipt(message,sender,respond){
   if(message?.type!=='detection-receipt'){return;}
   if(disposed||sender?.id!==api?.runtime?.id||sender?.tab||typeof message.fingerprint!=='string'||!(/^[0-9a-f]{64}$/).test(message.fingerprint)){respond({ok:false});return false;}
   const index=receipts.findIndex(entry=>entry.fingerprint===message.fingerprint),entry=index<0?null:receipts.splice(index,1)[0];
   respond(entry?{ok:true,delivery_id:entry.delivery_id,authority:entry.authority}:{ok:true,delivery_id:null});return false;
  }
  const attached=new Set();
  const fileNames=list=>Array.from(list||[]).map(file=>file?.name).filter(name=>typeof name==='string'&&name.length>0&&name.length<=200&&![...name].some(c=>c.codePointAt(0)<32||c.codePointAt(0)===127));
  function attach(list){if(!policy?.config.collection.store_file_names){return;}for(const name of fileNames(list)){if(attached.size>=20){return;}attached.add(name);}}
  // `knownResponses` is keyed by node identity. A provider that REPLACES a response's
  // node with another one carrying identical text — measured on copilot.microsoft.com on
  // 2026-09-14 — therefore escapes this guard and delivers the event twice. The text already
  // delivered for the current correlation is the only stable key; a correlation covers
  // only one send, so two identical responses under the same correlation cannot occur.
  const DELIVERED_RESPONSES=64;
  let knownResponses=new WeakMap(),responseTimers=new Map(),deliveredResponses=new Set(),responseBatchTimer=null,responseTargets=new Set(),responseRescan=false;const listeners=[];
  const withinLimit=text=>encoder.encode(text).length<=32768;
  async function message(value){
   let timer;const begin=win.performance.now(),wall=Date.now();
   // The loser of the race is never consumed: on every timeout, the send's later
   // rejection used to surface as "Uncaught (in promise)". Attaching a
   // handler changes neither the race's outcome nor the timeout.
   const envoi=Promise.resolve(send(value));envoi.catch(()=>{});
   try{const reply=await Promise.race([envoi,new Promise(resolve=>{timer=win.setTimeout(()=>resolve({ok:false,reason:'L’agent local ne répond pas.'}),8000);})]);
    const elapsed=win.performance.now()-begin,wallElapsed=Date.now()-wall;
    if(elapsed<0||wallElapsed<0||elapsed>=8000||wallElapsed>=8000||Math.abs(elapsed-wallElapsed)>1000||
       (reply?.mode==='grace'&&(!Number.isFinite(reply.remaining_ms)||reply.remaining_ms<=Math.max(elapsed,wallElapsed)))){return {ok:false,reason:'La validation a expiré. Réessayez.'};}
    return reply;
   }catch{return {ok:false};}finally{win.clearTimeout(timer);}
  }
  let restoreFocus;
  function close(){overlay?.remove();overlay=null;if(restoreFocus?.isConnected){restoreFocus.focus();}restoreFocus=null;}
  function notice(title,detail,text,accept,acceptLabel='Utiliser ce texte'){
   close();restoreFocus=document.activeElement;const host=document.createElement('div');host.style.cssText='all:initial;position:fixed;inset:0;z-index:2147483647';const shadow=host.attachShadow({mode:'closed'});
   const style=document.createElement('style');style.textContent=':host{color-scheme:light dark}.shade{position:fixed;inset:0;display:grid;place-items:center;background:#0008;font:15px/1.5 system-ui;color:#eee}.card{background:#202020;border:1px solid #888;border-radius:14px;padding:24px;width:min(540px,85vw);max-height:85vh;overflow:auto;box-shadow:0 15px 60px #0008}h2{font-size:21px;margin:0 0 12px}p{white-space:pre-wrap}textarea{width:100%;min-height:150px;box-sizing:border-box;background:#111;color:#fff;border:1px solid #999;padding:12px;font:inherit}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:12px}button{padding:10px 16px;border:1px solid #aaa;border-radius:7px;background:#eee;color:#111;font:inherit;cursor:pointer}button:focus-visible,textarea:focus-visible{outline:3px solid #aaa;outline-offset:3px}.signature{margin:16px 0 0;text-align:right;font-size:12px;opacity:.7}';
   const shade=document.createElement('div');shade.className='shade';const card=document.createElement('section');card.className='card';card.setAttribute('role','dialog');card.setAttribute('aria-modal','true');card.setAttribute('aria-label',t('Milvago — contrôle local'));
   const heading=document.createElement('h2');heading.textContent=t(title);const description=document.createElement('p');description.textContent=t(detail);card.append(heading,description);
   if(typeof text==='string'){const preview=document.createElement('textarea');preview.value=text;preview.readOnly=true;preview.setAttribute('aria-label',t('Texte contrôlé à envoyer'));card.append(preview);}
   // Buttons aligned right, the close button last — hence rightmost
   // (product decision of 2026-09-16).
   const actions=document.createElement('div');actions.className='actions';
   if(accept){const button=document.createElement('button');button.textContent=t(acceptLabel);button.onclick=()=>{close();accept();};actions.append(button);}
   const cancel=document.createElement('button');cancel.textContent=t(accept?'Annuler':'Fermer');cancel.onclick=close;actions.append(cancel);card.append(actions);
   // Edition signature, bottom right of each message. Empty, and therefore absent, in
   // the Proprietary edition: `build-editions.js` only populates the constant for
   // Community, so the branding cannot leak into the other package.
   if(COMMUNITY_SIGNATURE){const signature=document.createElement('p');signature.className='signature';signature.textContent=t(COMMUNITY_SIGNATURE);card.append(signature);}
   shade.append(card);shadow.append(style,shade);document.documentElement.append(host);overlay=host;cancel.focus();
   shadow.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();close();}if(event.key==='Tab'){const focusable=[...card.querySelectorAll('textarea,button')];const index=focusable.indexOf(shadow.activeElement),next=(index+(event.shiftKey?-1:1)+focusable.length)%focusable.length;event.preventDefault();focusable[next].focus();}});
  }
  async function emit(kind,text,action,labels,id,delivery_id){if(action===undefined){action='observed';}if(labels===undefined){labels=[];}if(id===undefined){id=correlation;}
   try{
   if(!policy?.config.collection.enabled){return false;}
   // `location.href` as the document sees it now. The service worker cannot read it:
   // `sender.url` is frozen at the URL the document was committed at, and every one of
   // these providers changes conversation without reloading. The worker keeps the last
   // word -- it accepts this URL only while it names the same provider it already
   // trusts the frame for.
   const event={kind,characters:Array.from(text).length,action,labels,url:location.href};if(id){event.correlation_id=id;}
   if(kind!=='navigation'&&policy.config.collection.store_content&&withinLimit(text)){event[kind]=text;}
   if(kind==='prompt'&&policy.config.collection.store_file_names&&attached.size){event.files=[...attached];}
   if(kind==='prompt'&&win.crypto.subtle){const digest=await win.crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));event.fingerprint=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');}
   // Recheck consent after asynchronous work, before passing any content.
   if(!policy?.config.collection.enabled){return false;}
   if(!policy.config.collection.store_content){delete event.prompt;delete event.response;}
   if(!policy.config.collection.store_file_names){delete event.files;}
   if(delivery_id){event.capture_id=delivery_id;}
   return (await message({type:'event',event}))?.ok===true;
   }catch{return false;}
  }
  function resetResponses(){if(responseBatchTimer){win.clearTimeout(responseBatchTimer);responseBatchTimer=null;}responseTargets.clear();responseRescan=false;for(const entry of responseTimers.values()){win.clearTimeout(entry.timer);}responseTimers.clear();deliveredResponses.clear();knownResponses=new WeakMap([...document.querySelectorAll(adapter.response)].map(node=>[node,A.read(node)]));}
  // One navigation record per conversation (or page) per half hour, shared by every
  // document of the browser profile. A refresh, a redirect that reloads the page, a tab
  // reloaded by an extension update and a prerendered document each start a new
  // content script, and each used to record a navigation of its own (two of them 326 ms
  // apart on 2026-09-11). A conversation not seen in the window is always recorded, so
  // a prompt that opens one keeps its link. Unavailable storage costs an extra record,
  // never a lost one.
  const NAVIGATION_WINDOW_MS=30*60*1000,NAVIGATION_KEYS=256;
  async function firstNavigation(context){
   const key=`${context.provider}|${context.conversation_id||context.url}`;
   try{
    const now=Date.now(),held=(await api.storage.local.get('navigations'))?.navigations||{};
    const kept={};for(const [k,at] of Object.entries(held)){if(typeof at==='number'&&now-at<NAVIGATION_WINDOW_MS){kept[k]=at;}}
    const seen=key in kept;kept[key]=now;
    for(const k of Object.keys(kept).slice(0,Math.max(0,Object.keys(kept).length-NAVIGATION_KEYS))){delete kept[k];}
    await api.storage.local.set({navigations:kept});
    return !seen;
   }catch{return true;}
  }
  function navigation(){if(!policy){return;}const context=A.context(location.href),url=context?.url;if(url===lastUrl){return;}const old=A.context(lastUrl);const newlyAssigned=correlation&&!old?.conversation_id&&context?.conversation_id;if(lastUrl&&!newlyAssigned){receipts.length=0;}lastUrl=url;if(!newlyAssigned){correlation=null;resetResponses();}draftEpoch++;attached.clear();draftCorrelation=null;if(!context){return;}const id=correlation;void firstNavigation(context).then(first=>{if(first&&!disposed){emit('navigation','','observed',[],id);}});}
  // A failed poll (slow agent, slow network) is not a policy change: we
  // keep the last known one. Clearing it used to change the pending send's snapshot, which
  // then failed with "Final validation or durable recording failed." The background rejects inspect/submit anyway
  // when the policy is not authorized.
  async function refresh(){const answer=await message({type:'policy'});if(answer.ok){policy=answer.policy;}if(policy){navigation();}}

  const policyState=()=>JSON.stringify(policy&&{version:policy.version,revision:policy.revision,config:policy.config});
  const state=()=>({url:location.href,policy:policyState(),epoch:draftEpoch,attempt});
  const unchanged=s=>!disposed&&s.url===location.href&&s.policy===policyState()&&s.epoch===draftEpoch&&s.attempt===attempt;
  async function submit(editor,text,intent,snapshot){
   const {control,form,target}=intent;
   if(!unchanged(snapshot)||!editor.isConnected||!target.isConnected||A.read(editor)!==text){return;}
   const deliveryCorrelation=draftCorrelation||win.crypto.randomUUID();pending=true;
   try{
    let submitDigest;
    try{if(win.crypto.subtle){submitDigest=await win.crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));}}catch{notice('Envoi en attente','Le lien avec le reçu durable est indisponible.');return;}
    if(!unchanged(snapshot)||A.read(editor)!==text){return;}
    const final=await message({type:'submit',text,upload:false,event:{kind:'prompt',action:'observed',characters:Array.from(text).length,labels:[],url:location.href,correlation_id:deliveryCorrelation,...(policy?.config.collection.store_file_names&&attached.size?{files:[...attached]}:{})}});
    if(!final.ok||final.action!=='observe'||final.text!==text||(final.recording_required!==false&&(final.durable!==true||!validReceipt(final.delivery_id)||(final.authority!==null&&!(typeof final.authority==='string'&&/^[0-9a-f]{64}$/.test(final.authority)))))||!unchanged(snapshot)||!editor.isConnected||!target.isConnected||A.read(editor)!==text||control?.disabled||control?.getAttribute('aria-disabled')==='true'){notice('Envoi en attente',final.reason||'La validation finale ou l’enregistrement durable a échoué.');return;}
    if(final.recording_required!==false&&final.durable===true&&validReceipt(final.delivery_id)){
     if(!submitDigest){notice('Envoi en attente','Le lien avec le reçu durable est indisponible.');return;}
     if(receipts.length>=128){receipts.shift();}
     receipts.push({fingerprint:Array.from(new Uint8Array(submitDigest),b=>b.toString(16).padStart(2,'0')).join(''),delivery_id:final.delivery_id,authority:final.authority});
    }
    correlation=deliveryCorrelation;draftCorrelation=null;resetResponses();attached.clear();close();
    replay={editor,text,target,form,clicked:false,submitted:false};
    try{if(control){control.click();}else {form.requestSubmit();}}finally{replay=null;}
   }finally{pending=false;}
  }
  async function handle(event){
   if(replay&&A.read(replay.editor)===replay.text){
    if(event.type==='click'&&event.target===replay.target&&!replay.clicked){replay.clicked=true;return;}
    if(event.type==='submit'&&event.target===replay.form&&!replay.submitted){replay.submitted=true;return;}
   }
   const editor=A.submission(adapter,event,document,draftCorrelation!==null);if(!editor){return;}const text=A.read(editor);
   stop(event);if(pending){return;}
   attempt++;const intent=A.submissionTarget(adapter,event,editor,document);
   if(!intent){notice('Envoi en attente','Ce contrôle ne permet pas de reprendre automatiquement l’envoi.');return;}
   if(!withinLimit(text)){notice('Envoi en attente','Le texte dépasse la limite du contrôle local (32 Kio). Réduisez-le avant de réessayer.');return;}
   const snapshot=state();pending=true;const answer=await message({type:'inspect',text,upload:false});pending=false;
   if(!unchanged(snapshot)||!editor.isConnected||A.read(editor)!==text){return;}
   if(!answer.ok){notice('Envoi en attente',answer.reason||'Connectez l’agent local puis réessayez.');return;}
   if(!['observe','review','block','redirect'].includes(answer.action)||typeof answer.text!=='string'||!withinLimit(answer.text)){notice('Envoi en attente','Réponse de contrôle non valide.');return;}
   const labels=Array.isArray(answer.labels)?answer.labels:[];
   if(answer.action==='block'){emit('prompt',text,'blocked',labels,win.crypto.randomUUID());const found=typeof answer.evidence==='string'&&answer.evidence.length<=200?`\n\nDétecté : ${answer.evidence}`:'';notice('Envoi bloqué',(answer.reason||'La politique locale bloque cet envoi.')+found);return;}
   if(answer.action==='redirect'){
    emit('prompt',text,'redirected',labels,win.crypto.randomUUID());let target;try{target=new URL(answer.redirect_url);if(target.protocol!=='https:'||target.username||target.password){throw new Error('Invalid redirect target');}}catch{notice('Redirection refusée','La destination de la politique est invalide.');return;}
    notice('Service autorisé',`${answer.reason||'Utilisez le service prévu par votre organisation.'}\n${target.origin}`,undefined,()=>location.assign(target.href),'Ouvrir le service');return;
   }
   const allow=async()=>{
    if(!unchanged(snapshot)||!editor.isConnected||A.read(editor)!==text){return;}
    // The submitted text is whatever the editor actually contains: the agent inspects it
    // again on submit and rejects any difference from what it approved.
    const applied=answer.text===text?text:A.write(editor,answer.text);
    if(applied===null){notice('Envoi en attente','Le texte contrôlé n’a pas pu être appliqué au brouillon.');return;}
    editor.focus();await submit(editor,applied,intent,state());
   };
   // Review text: product decision of 2026-09-16.
   if(answer.action==='review'||answer.text!==text){notice('Informations confidentielles','Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.',answer.text,allow,'Valider et envoyer');}
   else {await allow();}
  }
  // Opening a local picker transmits nothing. Intercept its change event instead,
  // when the actual selected FileList exists. Never read file contents.
  let uploadReplay;const fileSelections=new WeakMap();

  async function upload(event){
   if(event===uploadReplay){return;}
   if(!event.isTrusted){return;}
   const picker=['input','change'].includes(event.type)&&event.target?.matches?.('input[type="file"]');
   let transfer=null;if(event.type==='drop'){transfer=event.dataTransfer;}else if(event.type==='paste'){transfer=event.clipboardData;}
   const list=picker?event.target.files:transfer?.files;
   if(!list?.length){if(picker){attached.clear();draftCorrelation=null;draftEpoch++;fileSelections.delete(event.target);}return;}
   stop(event);
   if(picker&&event.type==='change'){const selection=fileSelections.get(event.target);if(selection?.changePending&&sameFiles(list,selection.files)){selection.changePending=false;return;}}
   draftEpoch++;if(pending){return;}
   const target=event.target,snapshot=state(),files=Array.from(list||[]);let resume;
   if(picker){fileSelections.set(target,{files,changePending:event.type==='input'});}
   // The event data store is readable only during dispatch. Preserve File references
   // synchronously; no contents or names are read here.
   if(picker){resume=new win.Event('change',{bubbles:true,cancelable:true});}
   else{
    if(typeof win.DataTransfer!=='function'){notice('Fichier en attente','Ce navigateur ne permet pas de reprendre ce transfert. Utilisez le sélecteur de fichiers.');return;}
    const copy=new win.DataTransfer();for(const file of files){copy.items.add(file);}
    if(!sameFiles(copy.files,files)){notice('Fichier en attente','La sélection de fichiers a changé.');return;}
    resume=event.type==='drop'?new win.DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:copy}):new win.ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:copy});
   }
   pending=true;
   try{
    const answer=await message({type:'inspect',text:'',upload:true});
    if(!unchanged(snapshot)||!target?.isConnected){return;}
    if(!answer.ok||answer.action!=='observe'){notice('Fichier en attente',answer.reason||'Le contrôle local refuse ce transfert.');return;}
    draftCorrelation=draftCorrelation||win.crypto.randomUUID();
    const final=await message({type:'submit',text:'',upload:true,event:{kind:'prompt',action:'observed',characters:0,labels:[],url:location.href,correlation_id:draftCorrelation,...(policy?.config.collection.store_file_names?{files:fileNames(files)}:{})}});
    if(!final.ok||final.action!=='observe'||final.text!==''||(final.recording_required!==false&&(final.durable!==true||!validReceipt(final.delivery_id)))||!unchanged(snapshot)||!target.isConnected){notice('Fichier en attente',final.reason||'La validation finale a échoué.');return;}let resumedFiles;if(picker){resumedFiles=target.files;}else if(event.type==='drop'){resumedFiles=resume.dataTransfer.files;}else {resumedFiles=resume.clipboardData.files;}if(!sameFiles(resumedFiles,files)){notice('Fichier en attente',final.reason||'La validation finale a échoué.');return;}
    if(picker){attached.clear();}attach(files);uploadReplay=resume;
    try{if(picker){const input=new win.Event('input',{bubbles:true,cancelable:false});uploadReplay=input;target.dispatchEvent(input);uploadReplay=resume;}target.dispatchEvent(resume);}finally{uploadReplay=null;}
   }finally{pending=false;}
  }
  function responses(nodes){if(!correlation||!policy?.config.collection.enabled){return;}
   for(const node of nodes||document.querySelectorAll(adapter.response)){
    const text=A.read(node);if(knownResponses.get(node)===text||deliveredResponses.has(text)||!text.trim()||!withinLimit(text)){continue;}
    const existing=responseTimers.get(node);if(existing?.text===text&&existing.id===correlation){continue;}
    if(existing){win.clearTimeout(existing.timer);}
    const entry={text,id:correlation,delivery_id:win.crypto.randomUUID(),retries:0,timer:null};responseTimers.set(node,entry);
    const collect=async()=>{
     if(disposed||!node.isConnected||entry.id!==correlation||responseTimers.get(node)!==entry){return;}
      if(A.read(node)!==entry.text){responseTimers.delete(node);responses([node]);return;}
     if(A.responseBusy(adapter,node,document)){entry.timer=win.setTimeout(collect,1200);return;}
     const inspectedPolicy=policyState(),inspected=await message({type:'inspect',text:entry.text,upload:false});
     if(disposed||entry.id!==correlation||responseTimers.get(node)!==entry){return;}
     if(A.read(node)!==entry.text||A.responseBusy(adapter,node,document)||inspectedPolicy!==policyState()){responseTimers.delete(node);responses();return;}
     let delivered=false;
     if(inspected.ok&&typeof inspected.text==='string'&&withinLimit(inspected.text)){delivered=await emit('response',inspected.text,'observed',inspected.labels||[],entry.id,entry.delivery_id);}
     if(delivered){knownResponses.set(node,entry.text);deliveredResponses.add(entry.text);if(deliveredResponses.size>DELIVERED_RESPONSES){deliveredResponses.delete(deliveredResponses.values().next().value);}responseTimers.delete(node);}
     else if(++entry.retries<3){entry.timer=win.setTimeout(collect,1200);}
     else {responseTimers.delete(node);}
    };
    entry.timer=win.setTimeout(collect,1200);
   }
  }
  function blocked(message){if(message?.type!=='model-blocked'){return;}attempt++;correlation=null;const en=document.documentElement.lang.startsWith('en');notice(en?'Request blocked':'Envoi bloqué',en?`Model: ${message.model||'unknown'}. Policy ${message.revision??'unavailable'}. ${message.reason==='model_denied'?'This model is forbidden.':'The requested model or transport cannot be verified.'}`:`Modèle : ${message.model||'indéterminé'}. Politique ${message.revision??'indisponible'}. ${message.reason==='model_denied'?'Ce modèle est interdit.':'Le modèle demandé ou le transport ne peut pas être vérifié.'}`);}
  api?.runtime?.onMessage?.addListener(blocked);
  api?.runtime?.onMessage?.addListener(receipt);
  function listen(type,fn){document.addEventListener(type,fn,true);listeners.push([type,fn]);}
  for(const type of ['submit','click','keydown']){listen(type,handle);}for(const type of ['input','change','drop','paste']){listen(type,upload);}listen('input',event=>{if(!event.target?.matches?.('input[type="file"]')){draftEpoch++;}});
  function responseNode(target){const element=target?.nodeType===win.Node.ELEMENT_NODE?target:target?.parentElement;return element?.closest?.(adapter.response)||null;}
  function observeResponses(records){
   for(const record of records){
    // Structural changes may add, replace or move a response. An attribute outside
    // a response may also be the global stop control consulted by responseBusy().
    if(record.type==='childList'){responseRescan=true;responseTargets.clear();break;}
    const node=responseNode(record.target);if(!node){responseRescan=true;responseTargets.clear();break;}responseTargets.add(node);
   }
   if(responseBatchTimer){return;}
   responseBatchTimer=win.setTimeout(()=>{responseBatchTimer=null;const nodes=responseRescan?null:[...responseTargets];responseTargets.clear();responseRescan=false;responses(nodes);},50);
  }
  const observer=new win.MutationObserver(observeResponses);observer.observe(document,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['data-is-streaming','aria-busy']});
  const navTimer=win.setInterval(navigation,1000),policyTimer=win.setInterval(refresh,30000);void refresh();
  return {handle,upload,refresh,navigation,dispose(){receipts.length=0;api?.runtime?.onMessage?.removeListener(receipt);api?.runtime?.onMessage?.removeListener(blocked);disposed=true;close();observer.disconnect();win.clearInterval(navTimer);win.clearInterval(policyTimer);for(const [type,fn]of listeners){document.removeEventListener(type,fn,true);}resetResponses();}};
 }
 globalThis.MilvagoCapture={start};
 if(api&&globalThis.document){void (async()=>{globalThis.__milvagoCapture?.dispose?.();globalThis.__milvagoCapture=true;try{const reply=await api.runtime.sendMessage({type:'catalog'});A.applyCatalog(reply?.catalog);}catch{}const running=start(document,location,message=>api.runtime.sendMessage(message));globalThis.__milvagoCapture=running||false;})();}
})();
