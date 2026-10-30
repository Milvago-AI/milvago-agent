(() => {
 const A=globalThis.MilvagoAdapters,api=globalThis.browser||globalThis.chrome;
 const encoder=new TextEncoder();
 function stop(event){event.preventDefault();event.stopImmediatePropagation();}
 function sameFiles(list,files){return list?.length===files.length&&files.every((file,index)=>list[index]===file);}
 function addCaptureID(event,delivery_id){if(delivery_id){event.capture_id=delivery_id;}}
 function replayedFiles(picker,event,target,resume){
   if(picker){return target.files;}
   if(event.type==='drop'){return resume.dataTransfer.files;}
   return resume.clipboardData.files;
  }
 function uploadSelection(event){
   const picker=['input','change'].includes(event.type)&&event.target?.matches?.('input[type="file"]');
   let transfer=null;if(event.type==='drop'){transfer=event.dataTransfer;}else if(event.type==='paste'){transfer=event.clipboardData;}
   const list=picker?event.target.files:transfer?.files;
   return {picker,list};
  }
 const COMMUNITY_SIGNATURE='';
 const TEXT=[["Confirmation requise", "Confirmation required", "Confirmación requerida", "Confirmação necessária"],["Vérifiez cet envoi avant de confirmer.", "Review this submission before confirming.", "Revise este envío antes de confirmar.", "Revise este envio antes de confirmar."],["Confirmer le transfert", "Confirm transfer", "Confirmar transferencia", "Confirmar transferência"],["La confirmation a expiré. Réessayez.", "Confirmation expired. Try again.", "La confirmación ha caducado. Inténtelo de nuevo.", "A confirmação expirou. Tente novamente."],["Envoi en attente","Send pending","Envío pendiente","Envio pendente"],["Fichier en attente","File pending","Archivo pendiente","Arquivo pendente"],["Fichier refusé","File refused","Archivo rechazado","Arquivo recusado"],["Envoi bloqué","Send blocked","Envío bloqueado","Envio bloqueado"],["Redirection refusée","Redirect refused","Redirección rechazada","Redirecionamento recusado"],["Service autorisé","Allowed service","Servicio autorizado","Serviço permitido"],["Informations confidentielles","Confidential information","Información confidencial","Informações confidenciais"],["Valider et envoyer","Confirm and send","Confirmar y enviar","Confirmar e enviar"],["Utiliser ce texte","Use this text","Usar este texto","Usar este texto"],["Annuler","Cancel","Cancelar","Cancelar"],["Fermer","Close","Cerrar","Fechar"],["Ouvrir le service","Open service","Abrir el servicio","Abrir o serviço"],["Milvago — contrôle local","Milvago — local inspection","Milvago — control local","Milvago — verificação local"],["Texte contrôlé à envoyer","Inspected text to send","Texto revisado para enviar","Texto verificado para enviar"],["Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.","The information you provided contains confidential information. Please review the elements we masked below before sending.","La información que has proporcionado contiene información confidencial. Revisa los elementos que hemos enmascarado a continuación antes de enviar.","As informações que você forneceu contêm informações confidenciais. Verifique os elementos que mascaramos abaixo antes de enviar."],["Ce contrôle ne permet pas de reprendre automatiquement l’envoi.","This control cannot resume sending automatically.","Este control no permite reanudar el envío automáticamente.","Este controle não permite retomar o envio automaticamente."],["Le texte dépasse la limite du contrôle local (32 Kio). Réduisez-le avant de réessayer.","The text exceeds the local inspection limit (32 KiB). Shorten it before retrying.","El texto supera el límite del control local (32 KiB). Redúcelo antes de volver a intentarlo.","O texto excede o limite da verificação local (32 KiB). Reduza-o antes de tentar novamente."],["Connectez l’agent local puis réessayez.","Connect the local agent and retry.","Conecta el agente local y vuelve a intentarlo.","Conecte o agente local e tente novamente."],["Réponse de contrôle non valide.","Invalid inspection response.","Respuesta de control no válida.","Resposta de verificação inválida."],["Le lien avec le reçu durable est indisponible.","The durable receipt link is unavailable.","El vínculo con el recibo persistente no está disponible.","O vínculo com o recibo persistente está indisponível."],["La validation finale ou l’enregistrement durable a échoué.","Final validation or durable recording failed.","La validación final o el registro persistente falló.","A validação final ou o registro persistente falhou."],["La validation finale a échoué.","Final validation failed.","La validación final falló.","A validação final falhou."],["La politique locale bloque cet envoi.","The local policy blocks this send.","La política local bloquea este envío.","A política local bloqueia este envio."],["La destination de la politique est invalide.","The policy destination is invalid.","El destino de la política no es válido.","O destino da política é inválido."],["Le texte contrôlé n’a pas pu être appliqué au brouillon.","The inspected text could not be applied to the draft.","No se pudo aplicar el texto revisado al borrador.","Não foi possível aplicar o texto verificado ao rascunho."],["Ce navigateur ne permet pas de reprendre ce transfert. Utilisez le sélecteur de fichiers.","This browser cannot resume this transfer. Use the file picker.","Este navegador no permite reanudar esta transferencia. Usa el selector de archivos.","Este navegador não permite retomar esta transferência. Use o seletor de arquivos."],["La sélection de fichiers a changé.","The file selection changed.","La selección de archivos cambió.","A seleção de arquivos mudou."],["Le contrôle local refuse ce transfert.","Local inspection refuses this transfer.","El control local rechaza esta transferencia.","A verificação local recusa esta transferência."],["L’agent local ne répond pas.","The local agent is not responding.","El agente local no responde.","O agente local não responde."],["La validation a expiré. Réessayez.","Validation expired. Retry.","La validación caducó. Vuelve a intentarlo.","A validação expirou. Tente novamente."],["Extension mise à jour : rechargez la page pour envoyer.","Extension updated: reload the page to send.","Extensión actualizada: recarga la página para enviar.","Extensão atualizada: recarregue a página para enviar."],["La zone de saisie contrôlée est introuvable ou ambiguë. Rechargez la page puis réessayez.","The inspected message box is missing or ambiguous. Reload the page and retry.","La zona de entrada controlada no se encuentra o es ambigua. Recarga la página y vuelve a intentarlo.","A caixa de mensagem verificada está ausente ou ambígua. Recarregue a página e tente novamente."],["Le bouton d’envoi du service est indisponible. Réessayez dans un instant.","The service’s send button is unavailable. Retry in a moment.","El botón de envío del servicio no está disponible. Vuelve a intentarlo en un momento.","O botão de envio do serviço está indisponível. Tente novamente em instantes."],["L’envoi n’a pas pu être repris automatiquement. Cliquez sur le bouton d’envoi du service.","The send could not be resumed automatically. Click the service’s send button.","No se pudo reanudar el envío automáticamente. Haz clic en el botón de envío del servicio.","Não foi possível retomar o envio automaticamente. Clique no botão de envio do serviço."],
 ["Cet envoi n’a pas été validé par le contrôle local. Renvoyez-le depuis la zone de saisie. Politique","This send was not validated by the local control. Send it again from the message box. Policy","Este envío no fue validado por el control local. Vuelve a enviarlo desde la zona de entrada. Política","Este envio não foi validado pela verificação local. Envie-o novamente pela caixa de mensagem. Política"],["indisponible","unavailable","no disponible","indisponível"],
 // Edition signature. The key is the French string, the one `build-editions.js`
 // injects into `COMMUNITY_SIGNATURE` for the Community edition only: `t()` then
 // translates it like any other label, so a language added to the table
 // covers it without touching the build script.
 ["Collage en cours de contrôle","Checking pasted text","Comprobando el texto pegado","Verificando o texto colado"],["Le texte collé est contrôlé localement avant d’être inséré.","The pasted text is checked locally before it is inserted.","El texto pegado se comprueba localmente antes de insertarse.","O texto colado é verificado localmente antes de ser inserido."],["Collage refusé","Paste refused","Pegado rechazado","Colagem recusada"],["Le texte collé dépasse la limite du contrôle local. Collez-le en plusieurs fois.","The pasted text exceeds the local inspection limit. Paste it in several parts.","El texto pegado supera el límite del control local. Pégalo en varias partes.","O texto colado excede o limite da verificação local. Cole-o em várias partes."],["Valider et coller","Confirm and paste","Confirmar y pegar","Confirmar e colar"],["Le texte contrôlé n’a pas pu être inséré.","The inspected text could not be inserted.","No se pudo insertar el texto revisado.","Não foi possível inserir o texto verificado."],
 ["Ce presse-papiers ne contient aucun texte que le contrôle local peut lire. Collez le contenu en texte brut.","This clipboard holds no text the local inspection can read. Paste the content as plain text.","Este portapapeles no contiene texto que el control local pueda leer. Pega el contenido como texto sin formato.","Esta área de transferência não contém texto que a verificação local possa ler. Cole o conteúdo como texto simples."],["Un collage est déjà en cours de contrôle. Réessayez quand il sera terminé.","A paste is already being checked. Retry once it is done.","Ya se está comprobando un pegado. Vuelve a intentarlo cuando termine.","Uma colagem já está sendo verificada. Tente novamente quando terminar."],
 ["Sécurisé par Milvago Community","Secured by Milvago Community","Protegido por Milvago Community","Protegido pelo Milvago Community"]];

 function start(document,location,send){
  const adapter=A.resolve(location.href);if(!adapter){return null;}
  const win=document.defaultView;
  const language=()=>{const value=(document.documentElement.lang||win.navigator.language||'fr').toLowerCase();if(value.startsWith('en')){return 1;}if(value.startsWith('es')){return 2;}if(value.startsWith('pt')){return 3;}return 0;};
  const t=value=>TEXT.find(row=>row[0]===value)?.[language()]||value;
  let policy,overlay,pending=false,uploading=null,correlation,lastUrl='',replay,continuation=null,disposed=false,draftEpoch=0,attempt=0;
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
  const receipts=[],LONE_MS=10000;let lastEmpty=null;
  const validReceipt=value=>typeof value==='string'&&A.RECEIPT_ID.test(value);
  function receipt(message,sender,respond){
   if(message?.type!=='detection-receipt'){return;}
   if(disposed||sender?.id!==api?.runtime?.id||sender?.tab||typeof message.fingerprint!=='string'||!(/^[0-9a-f]{64}$/).test(message.fingerprint)){respond({ok:false});return false;}
   const index=receipts.findIndex(entry=>entry.fingerprints.includes(message.fingerprint)),entry=index<0?null:receipts.splice(index,1)[0];
   // Named through a chip the DOM read as its preview only: the request carried more than this record holds.
   if(entry){respond({ok:true,delivery_id:entry.delivery_id,authority:entry.authority,...(entry.chips.includes(message.fingerprint)?{chip:true,correlation_id:entry.correlation}:{})});return false;}
   // A send without text in the draft (a pasted chip, an attachment) leaves with a body the DOM never
   // saw: its network record is not this one, but belongs to the same exchange (real campaign 0.7.8).
   const lone=lastEmpty&&Date.now()-lastEmpty.at<=LONE_MS?lastEmpty:null;lastEmpty=null;
   respond({ok:true,delivery_id:null,...(lone?{correlation_id:lone.correlation}:{})});return false;
  }
  const attached=new Set();
  const fileNames=list=>Array.from(list||[]).map(file=>file?.name).filter(name=>typeof name==='string'&&name.length>0&&name.length<=200&&![...name].some(c=>c.codePointAt(0)<32||c.codePointAt(0)===127));
  function attach(list){if(!policy?.config.collection.store_file_names){return;}for(const name of fileNames(list)){if(attached.size>=20){return;}attached.add(name);}}
  // `knownResponses` is keyed by node identity. A provider that REPLACES a response's
  // node with another one carrying identical text — measured on a provider page on
  // 2026-09-14 — therefore escapes this guard and delivers the event twice. The text already
  // delivered for the current correlation is the only stable key; a correlation covers
  // only one send, so two identical responses under the same correlation cannot occur.
  const DELIVERED_RESPONSES=64;
  let knownResponses=new WeakMap(),responseTimers=new Map(),deliveredResponses=new Set(),responseBatchTimer=null,responseTargets=new Set(),responseRescan=false;const listeners=[];
  const withinLimit=text=>encoder.encode(text).length<=32768;
  async function message(value,limit=8000){
   let timer;const begin=win.performance.now(),wall=Date.now();
   // The loser of the race is never consumed: on every timeout, the send's later
   // rejection used to surface as "Uncaught (in promise)". Attaching a
   // handler changes neither the race's outcome nor the timeout.
   let envoi;try{envoi=Promise.resolve(send(value));}catch(error){envoi=Promise.reject(error);}envoi.catch(()=>{});
   try{const reply=await Promise.race([envoi,new Promise(resolve=>{timer=win.setTimeout(()=>resolve({ok:false,reason:'L’agent local ne répond pas.'}),limit);})]);
    const elapsed=win.performance.now()-begin,wallElapsed=Date.now()-wall;
    if(elapsed<0||wallElapsed<0||elapsed>=limit||wallElapsed>=limit||Math.abs(elapsed-wallElapsed)>1000||
       (reply?.mode==='grace'&&(!Number.isFinite(reply.remaining_ms)||reply.remaining_ms<=Math.max(elapsed,wallElapsed)))){return {ok:false,reason:'La validation a expiré. Réessayez.'};}
    return reply;
   }catch(error){return orphaned(error)?{ok:false,reason:'Extension mise à jour : rechargez la page pour envoyer.'}:{ok:false};}finally{win.clearTimeout(timer);}
  }
  // This document outlived its extension: the worker it talks to is gone, and the new one never
  // injected a script here. Every send is then refused with a reason, never dropped in silence.
  function orphaned(error){return /context invalidated/i.test(String(error?.message))||(!!api?.runtime&&!api.runtime.id);}
  const usable=control=>control.isConnected&&!control.disabled&&control.getAttribute('aria-disabled')!=='true';
  // A send button greyed for a moment (the page validating the draft) gets a short grace period.
  // An attachment still uploading greys the button for seconds (real campaign 0.7.8, a long paste or an image):
  // the send waits for it. Nothing is approved before: the text is inspected again once it is usable.
  async function enabled(control){for(let i=0;i<100&&!usable(control);i++){await new Promise(resolve=>win.setTimeout(resolve,100));}return usable(control);}
  function replayKey(editor){for(const type of ['keydown','keyup']){editor.dispatchEvent(new win.KeyboardEvent(type,{key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true,cancelable:true,composed:true}));}}
  let restoreFocus,dismissed=null;
  // `dismissed`: the notice the person closed themselves, as opposed to one another notice replaced.
  let noticeCancel;
  function dismiss(){const cancelled=noticeCancel;noticeCancel=undefined;dismissed=overlay;close();cancelled?.();}
  let ontop=null;
  function close(){noticeCancel=undefined;win.clearInterval(ontop);ontop=null;overlay?.remove();overlay=null;if(restoreFocus?.isConnected){restoreFocus.focus();}restoreFocus=null;}
  function notice(title,detail,text,accept,acceptLabel='Utiliser ce texte',cancelled){
   close();noticeCancel=cancelled;restoreFocus=document.activeElement;const host=document.createElement('div');host.style.cssText='all:initial;position:fixed;inset:0;z-index:2147483647';const shadow=host.attachShadow({mode:'closed'});
   const style=document.createElement('style');style.textContent=':host{color-scheme:light dark}dialog{position:fixed;inset:0;margin:0;padding:0;border:0;width:100%;height:100%;max-width:none;max-height:none;background:transparent;color:inherit}dialog::backdrop{background:transparent}.shade{position:fixed;inset:0;display:grid;place-items:center;background:#0008;font:15px/1.5 system-ui;color:#eee}.card{background:#202020;border:1px solid #888;border-radius:14px;padding:24px;width:min(540px,85vw);max-height:85vh;overflow:auto;box-shadow:0 15px 60px #0008}h2{font-size:21px;margin:0 0 12px}p{white-space:pre-wrap}textarea{width:100%;min-height:150px;box-sizing:border-box;background:#111;color:#fff;border:1px solid #999;padding:12px;font:inherit}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:12px}button{padding:10px 16px;border:1px solid #aaa;border-radius:7px;background:#eee;color:#111;font:inherit;cursor:pointer}button:focus-visible,textarea:focus-visible{outline:3px solid #aaa;outline-offset:3px}.signature{margin:16px 0 0;text-align:right;font-size:12px;opacity:.7}';
   const shade=document.createElement('div');shade.className='shade';const card=document.createElement('section');card.className='card';card.setAttribute('role','dialog');card.setAttribute('aria-modal','true');card.setAttribute('aria-label',t('Milvago — contrôle local'));
   const heading=document.createElement('h2');heading.textContent=t(title);const description=document.createElement('p');description.textContent=t(detail);card.append(heading,description);
   if(typeof text==='string'){const preview=document.createElement('textarea');preview.value=text;preview.readOnly=true;preview.setAttribute('aria-label',t('Texte contrôlé à envoyer'));card.append(preview);}
   // Buttons aligned right, the close button last — hence rightmost
   // (product decision of 2026-09-16).
   const actions=document.createElement('div');actions.className='actions';
   if(accept){const button=document.createElement('button');button.textContent=t(acceptLabel);button.onclick=()=>{close();accept();};actions.append(button);}
   const cancel=document.createElement('button');cancel.textContent=t(accept?'Annuler':'Fermer');cancel.onclick=dismiss;actions.append(cancel);card.append(actions);
   // Edition signature, bottom right of each message. Empty, and therefore absent, in
   // the Proprietary edition: `build-editions.js` only populates the constant for
   // Community, so the branding cannot leak into the other package.
   if(COMMUNITY_SIGNATURE){const signature=document.createElement('p');signature.className='signature';signature.textContent=t(COMMUNITY_SIGNATURE);card.append(signature);}
   // In the top layer, as a modal dialog: a page's own modal window (real campaign 0.7.11) sat
   // above the highest z-index and made the notice inert. Shown again, a few times, if the page puts one back above it.
   shade.append(card);const box=document.createElement('dialog');box.append(shade);box.addEventListener('cancel',event=>event.preventDefault());
   shadow.append(style,box);document.documentElement.append(host);overlay=host;
   const modal=()=>{try{if(box.open){box.close();}box.showModal();}catch{box.setAttribute('open','');}};
   modal();cancel.focus();
   let tries=0;
   ontop=win.setInterval(()=>{const r=card.getBoundingClientRect(),hit=document.elementFromPoint?.(r.left+r.width/2,r.top+r.height/2);if(hit&&hit!==host&&tries++<20){modal();cancel.focus();}},300);
   shadow.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();dismiss();}if(event.key==='Tab'){const focusable=[...card.querySelectorAll('textarea,button')];const index=focusable.indexOf(shadow.activeElement),next=(index+(event.shiftKey?-1:1)+focusable.length)%focusable.length;event.preventDefault();focusable[next].focus();}});
  }

  async function textFingerprint(text){const digest=await win.crypto.subtle.digest('SHA-256',new TextEncoder().encode(text));return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');}
  async function emit(kind,text,action,labels,id,delivery_id,extra={}){if(action===undefined){action='observed';}if(labels===undefined){labels=[];}if(id===undefined){id=correlation;}
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
   // Why a send was refused, and the refused files' names (still dropped below without consent).
   if(extra.files){event.files=extra.files;}if(extra.decision_reason){event.decision_reason=extra.decision_reason;}
    if(kind==='prompt'&&win.crypto.subtle){event.fingerprint=await textFingerprint(text);}
   // Recheck consent after asynchronous work, before passing any content.
   if(!policy?.config.collection.enabled){return false;}
   if(!policy.config.collection.store_content){delete event.prompt;delete event.response;}
   if(!policy.config.collection.store_file_names){delete event.files;}
   addCaptureID(event,delivery_id);
   return (await message({type:'event',event}))?.ok===true;
   }catch{return false;}
  }
  function resetResponses(){if(responseBatchTimer){win.clearTimeout(responseBatchTimer);responseBatchTimer=null;}responseTargets.clear();responseRescan=false;const late=[...responseTimers].filter(([,entry])=>entry.waits>0&&entry.waits<=THINKING_WAITS);for(const entry of responseTimers.values()){win.clearTimeout(entry.timer);}responseTimers.clear();deliveredResponses.clear();const rows=turns();knownResponses=new WeakMap();for(const node of document.querySelectorAll(adapter.response)){const lead=turn(node,rows)[0];if(!knownResponses.has(lead)){knownResponses.set(lead,answerOf(lead,rows));}}
   // A short answer ending in an ellipsis still waited out belongs to the send before this one: taken now, as it is.
   for(const [node,entry] of late){entry.final=true;responseTimers.set(node,entry);entry.timer=win.setTimeout(entry.collect,0);}}
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
  function navigation(){if(!policy){return;}const context=A.context(location.href),url=context?.url;if(url===lastUrl){return;}const old=A.context(lastUrl);const newlyAssigned=correlation&&!old?.conversation_id&&context?.conversation_id;if(lastUrl&&!newlyAssigned){receipts.length=0;chipTexts.length=0;}lastUrl=url;if(!newlyAssigned){correlation=null;resetResponses();}draftEpoch++;attached.clear();draftCorrelation=null;if(!context){return;}const id=correlation;void firstNavigation(context).then(first=>{if(first&&!disposed){emit('navigation','','observed',[],id);}});}
  // A failed poll (slow agent, slow network) is not a policy change: we
  // keep the last known one. Clearing it used to change the pending send's snapshot, which
  // then failed with "Final validation or durable recording failed." The background rejects inspect/submit anyway
  // when the policy is not authorized.
  async function refresh(){const answer=await message({type:'policy'});if(answer.ok){policy=answer.policy;}if(policy){navigation();}}

  const policyState=()=>JSON.stringify(policy&&{version:policy.version,revision:policy.revision,config:policy.config});
  const state=()=>({url:location.href,policy:policyState(),epoch:draftEpoch,attempt});
  const unchanged=s=>!disposed&&s.url===location.href&&s.policy===policyState()&&s.epoch===draftEpoch&&s.attempt===attempt;
  function invalidSubmit(final,text,snapshot,editor,target,control){return !final.ok||final.action!=='observe'||final.text!==text||(final.recording_required!==false&&(final.durable!==true||!validReceipt(final.delivery_id)||(final.authority!==null&&!(typeof final.authority==='string'&&/^[0-9a-f]{64}$/.test(final.authority)))))||!unchanged(snapshot)||!editor.isConnected||!target.isConnected||A.read(editor)!==text||control?.disabled||control?.getAttribute('aria-disabled')==='true';}
  // Hashing is optional (no SubtleCrypto in some contexts) but a hashing failure must stop the send.
  async function receiptDigest(text){
   // The page may send the draft trimmed (ChatGPT with an attachment, real campaign 0.7.9): the same send, one receipt.
   // A rich editor's `innerText` doubles the break between two paragraphs while the page sends one (real campaign
   // 0.7.10: a masked paste of three lines, read 65 characters, sent 63): the same send too.
   const hash=value=>win.crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)),trimmed=text.trim(),single=trimmed.replaceAll('\n\n','\n');
   try{return {digest:win.crypto.subtle?await hash(text):undefined,trimmed:win.crypto.subtle&&trimmed&&trimmed!==text?await hash(trimmed):undefined,single:win.crypto.subtle&&single&&single!==trimmed?await hash(single):undefined};}catch{return null;}
  }
  // An editor may keep a long paste as a chip that shows only its start, blanks collapsed (100 characters, no
  // ellipsis, measured 2026-10-17), read before a line break and the draft, while the request carries the whole
  // paste then the draft less the space the editor puts after the chip. The trusted pastes of this document are
  // held here, in memory only, so the receipt also names that request (real campaign 0.7.11: two prompts).
  const chipTexts=[],CHIP_PREVIEW=100;
  function rememberPaste(text){if(typeof text!=='string'||!text.trim()||encoder.encode(text).length>PASTE_LIMIT){return;}const at=chipTexts.indexOf(text);if(at>=0){chipTexts.splice(at,1);}chipTexts.push(text);if(chipTexts.length>4){chipTexts.shift();}}
  async function chipDigests(text){
   const out=[];
   try{
    for(const chip of [...chipTexts].reverse()){
     const preview=chip.trim().replaceAll(/\s+/g,' ').slice(0,CHIP_PREVIEW);if(!text.startsWith(preview+'\n')){continue;}
     const rest=text.slice(preview.length+1);
     for(const draft of new Set([rest.replace(/^ /,''),rest.trim()])){out.push(await win.crypto.subtle.digest('SHA-256',encoder.encode(chip+draft)));}
    }
   }catch{return [];}
   return out;
  }
  const receiptRequired=final=>final.recording_required!==false&&final.durable===true&&validReceipt(final.delivery_id);
  function storeReceipt(final,digests,chips,correlation){
   if(receipts.length>=128){receipts.shift();}
   const hex=list=>list.filter(Boolean).map(digest=>Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join(''));
   receipts.push({fingerprints:hex([...digests,...chips]),chips:hex(chips),correlation,delivery_id:final.delivery_id,authority:final.authority});
  }
  const submitEvent=(text,deliveryCorrelation)=>({kind:'prompt',action:'observed',characters:Array.from(text).length,labels:[],url:location.href,correlation_id:deliveryCorrelation,...(policy?.config.collection.store_file_names&&attached.size?{files:[...attached]}:{})});
  async function submit(editor,text,intent,snapshot,approvalId){
   const {control,form,target}=intent;
   if(!unchanged(snapshot)||!editor.isConnected||!target.isConnected||A.read(editor)!==text){return;}
   const deliveryCorrelation=draftCorrelation||win.crypto.randomUUID();pending=true;
   try{
    if(control&&!(await enabled(control))){notice('Envoi en attente','Le bouton d’envoi du service est indisponible. Réessayez dans un instant.');return;}
    const hashed=await receiptDigest(text);
    if(!hashed){notice('Envoi en attente','Le lien avec le reçu durable est indisponible.');return;}
    const submitDigest=hashed.digest;
    if(!unchanged(snapshot)||A.read(editor)!==text){return;}
    const final=await message({type:'submit',text,upload:false,event:submitEvent(text,deliveryCorrelation),...(approvalId?{approval_id:approvalId}:{})});
    if(invalidSubmit(final,text,snapshot,editor,target,control)){notice('Envoi en attente',final.reason||'La validation finale ou l’enregistrement durable a échoué.');return;}
    if(receiptRequired(final)){
     if(!submitDigest){notice('Envoi en attente','Le lien avec le reçu durable est indisponible.');return;}
     // claude.ai's empty composer reads "\n" (ProseMirror's trailing break, real campaign 0.7.10): no text either.
     storeReceipt(final,[submitDigest,hashed.trimmed,hashed.single],await chipDigests(text),deliveryCorrelation);lastEmpty=text.trim()?null:{correlation:deliveryCorrelation,at:Date.now()};
    }
    correlation=deliveryCorrelation;draftCorrelation=null;resetResponses();attached.clear();close();
    replay={editor,text,target,form,clicked:false,submitted:false};
    try{if(control){control.click();}else if(form){form.requestSubmit();}else {replayKey(editor);}}finally{replay=null;}
    // A replayed key the page ignored leaves the draft in place: say so rather than wait in silence.
    if(intent.key){win.setTimeout(()=>{if(!disposed&&!overlay&&editor.isConnected&&A.read(editor)===text){notice('Envoi en attente','L’envoi n’a pas pu être repris automatiquement. Cliquez sur le bouton d’envoi du service.');}},1500);}
    // Anonymous ChatGPT answers the resubmission by calling form.requestSubmit() itself
    // once its sentinel tokens are ready (measured 32 ms later on 2026-09-29). That
    // trusted submit carries the text just approved and recorded: it is the same send,
    // not a new one, and recording it again counted every first message twice.
    const resubmitted=form||control?.form;
    continuation=resubmitted?{form:resubmitted,editor,text,until:Date.now()+2000}:null;
   }finally{pending=false;}
  }
  function onBlockedInspection(answer,text,labels,title='Envoi bloqué'){if(!answer.dlp_recorded){emit('prompt',text,'blocked',labels,win.crypto.randomUUID(),undefined,labels.includes('keyword')?{decision_reason:'keyword'}:{});}const found=typeof answer.evidence==='string'&&answer.evidence.length<=200?`\n\nDétecté : ${answer.evidence}`:'';notice(title,(answer.reason||'La politique locale bloque cet envoi.')+found);}
  function onRedirectInspection(answer,text,labels){
    emit('prompt',text,'redirected',labels,win.crypto.randomUUID());let target;try{target=new URL(answer.redirect_url);if(target.protocol!=='https:'||target.username||target.password){throw new Error('Invalid redirect target');}}catch{notice('Redirection refusée','La destination de la politique est invalide.');return;}
    notice('Service autorisé',`${answer.reason||'Utilisez le service prévu par votre organisation.'}\n${target.origin}`,undefined,()=>location.assign(target.href),'Ouvrir le service');
  }
  function warningReceipts(answer){const ids=Array.isArray(answer.dlp_receipts)?answer.dlp_receipts:[answer.dlp_receipt];return ids.length>0&&ids.length<=32&&ids.every(validReceipt)?ids:null;}
  async function acknowledgeWarning(answer){
   const ids=warningReceipts(answer);if(!ids)return false;
   for(const receipt of ids){const ack=await message({type:'dlp-confirmed',receipt});if(ack?.ok!==true||ack?.applied!==true)return false;}
   return true;
  }
  function cancelWarning(answer){for(const receipt of warningReceipts(answer)||[]){void message({type:'dlp-cancelled',receipt});}}
  async function confirmUpload(answer){
   if(!warningReceipts(answer))return false;
   return new Promise(resolve=>{
    let done=false,accepting=false,watch,timeout,shown;
    const finish=value=>{if(done)return;done=true;win.clearInterval(watch);win.clearTimeout(timeout);resolve(value);};
    notice('Confirmation requise',answer.reason||'Vérifiez cet envoi avant de confirmer.',undefined,async()=>{accepting=true;finish(await acknowledgeWarning(answer));},'Confirmer le transfert',()=>{cancelWarning(answer);finish(false);});
    shown=overlay;
    watch=win.setInterval(()=>{if(disposed||!accepting&&overlay!==shown)finish(false);},100);
    timeout=win.setTimeout(()=>{if(overlay===shown)close();cancelWarning(answer);finish(false);},10*60*1000);
   });
  }
  async function completeInspection(answer,editor,text,intent,snapshot){
   const labels=Array.isArray(answer.labels)?answer.labels:[];
   if(answer.action==='block'){onBlockedInspection(answer,text,labels);return;}
   if(answer.action==='redirect'){onRedirectInspection(answer,text,labels);return;}
   const allow=async()=>{
    if(!unchanged(snapshot)||!editor.isConnected||A.read(editor)!==text){return;}
    let approvalId;if(answer.confirmation===true){if(!(await acknowledgeWarning(answer))){notice('Envoi en attente','La confirmation a expiré. Réessayez.');return;}approvalId=answer.dlp_receipt;if(!unchanged(snapshot)||A.read(editor)!==text)return;}
    // The submitted text is whatever the editor actually contains: the agent inspects it
    // again on submit and rejects any difference from what it approved.
    // Held while the draft is rewritten: a send in that window would inspect a half-written draft.
    let applied=text;if(answer.text!==text){pending=true;try{applied=await A.write(editor,answer.text);}finally{pending=false;}}
    if(applied===null){notice('Envoi en attente','Le texte contrôlé n’a pas pu être appliqué au brouillon.');return;}
    editor.focus();await submit(editor,applied,intent,state(),approvalId);
   };
   // Review text: product decision of 2026-09-16.
   if(answer.confirmation===true){notice('Confirmation requise',answer.reason||'Vérifiez cet envoi avant de confirmer.',answer.text,allow,'Valider et envoyer',()=>cancelWarning(answer));}
   else if(answer.action==='review'||answer.text!==text){notice('Informations confidentielles','Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.',answer.text,allow,'Valider et envoyer',()=>{if(answer.dlp_receipt){void message({type:'dlp-cancelled',receipt:answer.dlp_receipt});}});}
   else {await allow();}
  }
  // True when the event is our own replayed click/submit or the page's follow-up submit of it.
  function isOwnReplay(event){
   if(replay&&A.read(replay.editor)===replay.text){
    if(event.type==='click'&&event.target===replay.target&&!replay.clicked){replay.clicked=true;return true;}
    if(event.type==='submit'&&event.target===replay.form&&!replay.submitted){replay.submitted=true;return true;}
   }
   if(continuation&&event.type==='submit'){
    const next=continuation;continuation=null;
    if(event.target===next.form&&Date.now()<next.until&&A.read(next.editor)===next.text){return true;}
   }
   return false;
  }
  const validInspection=answer=>['observe','review','block','redirect'].includes(answer.action)&&typeof answer.text==='string'&&withinLimit(answer.text);
  async function handle(event){
   if(isOwnReplay(event)){return;}
   const editor=A.submission(adapter,event,document,draftCorrelation!==null||uploading!==null);
   if(editor===false){stop(event);if(!pending){notice('Envoi en attente','La zone de saisie contrôlée est introuvable ou ambiguë. Rechargez la page puis réessayez.');}return;}
   if(!editor){return;}const text=A.read(editor);
   stop(event);
   if(pending){
    // A send pressed while the file just chosen is checked (about 1 s, real campaign 0.7.9) waits for it, then
    // goes through the whole check below with the same draft. A refused file or a changed draft drops it.
    const wait=uploading;if(!wait||!(await wait)||pending||!editor.isConnected||A.read(editor)!==text){return;}
   }
   await inspectSend(event,editor,text);
  }
  async function inspectSend(event,editor,text){
   attempt++;const intent=A.submissionTarget(adapter,event,editor,document);
   if(!intent){notice('Envoi en attente','Ce contrôle ne permet pas de reprendre automatiquement l’envoi.');return;}
   if(!withinLimit(text)){notice('Envoi en attente','Le texte dépasse la limite du contrôle local (32 Kio). Réduisez-le avant de réessayer.');return;}
   const snapshot=state();pending=true;let answer;try{answer=await message({type:'inspect',text,upload:false});}finally{pending=false;}
   if(!unchanged(snapshot)||!editor.isConnected||A.read(editor)!==text){return;}
   if(!answer.ok){notice('Envoi en attente',answer.reason||'Connectez l’agent local puis réessayez.');return;}
   if(!validInspection(answer)){notice('Envoi en attente','Réponse de contrôle non valide.');return;}
   await completeInspection(answer,editor,text,intent,snapshot);
  }
  // Opening a local picker transmits nothing. Intercept its change event instead,
  // when the actual selected FileList exists. Never read file contents.
  let uploadReplay;const fileSelections=new WeakMap();

  function createUploadReplay(event,picker,files){
   if(picker){return new win.Event('change',{bubbles:true,cancelable:true});}
   else{
    if(typeof win.DataTransfer!=='function'){notice('Fichier en attente','Ce navigateur ne permet pas de reprendre ce transfert. Utilisez le sélecteur de fichiers.');return null;}
    const copy=new win.DataTransfer();for(const file of files){copy.items.add(file);}
    if(!sameFiles(copy.files,files)){notice('Fichier en attente','La sélection de fichiers a changé.');return null;}
    return event.type==='drop'?new win.DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:copy}):new win.ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:copy});
   }
  }

  async function inspectUpload(event,picker,target,snapshot,files,resume){
   pending=true;
   try{
    const answer=await message({type:'inspect',text:'',upload:true});
    if(!unchanged(snapshot)||!target?.isConnected){return;}
    // A refusal by the policy is final and recorded; a control that did not answer may be retried.
    if(answer.ok&&answer.action==='block'){if(!answer.dlp_recorded){void emit('prompt','','blocked',Array.isArray(answer.labels)?answer.labels:[],win.crypto.randomUUID(),undefined,{decision_reason:'upload_blocked',...(policy?.config.collection.store_file_names?{files:fileNames(files)}:{})});}notice('Fichier refusé',answer.reason||'Le contrôle local refuse ce transfert.');return;}
    let approvalId;if(answer.ok&&answer.action==='review'&&answer.confirmation===true){if(!(await confirmUpload(answer)))return;approvalId=answer.dlp_receipt;if(!unchanged(snapshot)||!target.isConnected)return;}
    else if(!answer.ok||answer.action!=='observe'){notice('Fichier en attente',answer.reason||'Le contrôle local refuse ce transfert.');return;}
    draftCorrelation=draftCorrelation||win.crypto.randomUUID();
    // Each file by the fingerprint of its name and its size: the worker approves a text file of the
    // selection on them, once, without ever holding the name.
    const named=win.crypto.subtle?await Promise.all(files.filter(file=>typeof file?.name==='string'&&file.name&&Number.isSafeInteger(file.size)).slice(0,20).map(async file=>({name:await textFingerprint(file.name),size:file.size}))):[];
    const final=await message({type:'submit',text:'',upload:true,files:named,...(approvalId?{approval_id:approvalId}:{}),event:{kind:'prompt',action:'observed',characters:0,labels:[],url:location.href,correlation_id:draftCorrelation,...(policy?.config.collection.store_file_names?{files:fileNames(files)}:{})}});
    if(!final.ok||final.action!=='observe'||final.text!==''||(final.recording_required!==false&&(final.durable!==true||!validReceipt(final.delivery_id)))||!unchanged(snapshot)||!target.isConnected){notice('Fichier en attente',final.reason||'La validation finale a échoué.');return;}
    const resumedFiles=replayedFiles(picker,event,target,resume);
    if(!sameFiles(resumedFiles,files)){notice('Fichier en attente',final.reason||'La validation finale a échoué.');return;}
    if(picker){attached.clear();}attach(files);uploadReplay=resume;
    try{if(picker){const input=new win.Event('input',{bubbles:true,cancelable:false});uploadReplay=input;target.dispatchEvent(input);uploadReplay=resume;}target.dispatchEvent(resume);}finally{uploadReplay=null;}
    return true;
   }finally{pending=false;}
  }

  async function upload(event){
   if(event===uploadReplay){return;}
   if(!event.isTrusted){return;}
   const {picker,list}=uploadSelection(event);
   if(!list?.length){if(picker){attached.clear();draftCorrelation=null;draftEpoch++;fileSelections.delete(event.target);}return;}
   stop(event);
   if(picker&&event.type==='change'){const selection=fileSelections.get(event.target);if(selection?.changePending&&sameFiles(list,selection.files)){selection.changePending=false;return;}}
   draftEpoch++;if(pending){return;}
   const target=event.target,snapshot=state(),files=Array.from(list||[]);
   if(picker){fileSelections.set(target,{files,changePending:event.type==='input'});}
   // The event data store is readable only during dispatch. Preserve File references
   // synchronously; no contents or names are read here.
   const resume=createUploadReplay(event,picker,files);if(!resume){return;}
   const run=inspectUpload(event,picker,target,snapshot,files,resume).catch(()=>false);uploading=run;
   try{await run;}finally{if(uploading===run){uploading=null;}}
  }
  // Pasted or dropped text under masking: held in the capture phase before any page handler,
  // inspected by the agent (in pieces when long), shown for review when masked, then given to the
  // page as plain text only. The reinjected event is untrusted, the one mark a page cannot forge.
  // Only the composer is held: the provider's editor, or a field or rich editor in its form. Before
  // the policy is known a paste is held too: the agent answers the same for a policy that does not
  // mask. A file in the clipboard is left to `upload()`.
  const PASTE_LIMIT=192*1024,PASTE_TYPES=['insertFromPaste','insertFromDrop','insertFromPasteAsQuotation'];
  const masking=()=>{const config=policy?.config,protection=config?.protection;return !policy||!!(config?.dlp_control?.enabled||config?.privacy?.enabled||(protection?.keywords?.length&&['exact','unicode','fuzzy'].some(k=>protection[k]==='block')));};
  let draggingInside=false,pasting=false;
  function transferOf(event){
   if(event.type==='paste'){return event.clipboardData;}
   if(event.type==='drop'||(event.type==='beforeinput'&&PASTE_TYPES.includes(event.inputType))){return event.dataTransfer;}
   return undefined;
  }
  function composerField(target){
   const field=target.closest(adapter.editor)||target.closest('textarea,[contenteditable]:not([contenteditable="false"])');
   if(!field){return null;}
   return field.matches(adapter.editor)||field.closest('form')?.querySelector(adapter.editor)?field:null;
  }
  // HTML is read, never rendered nor reinjected: a parsed document runs no script and loads nothing.
  function pastedText(transfer){
   const plain=transfer?.getData?.('text/plain')||'';if(plain){return plain;}
   const html=transfer?.getData?.('text/html')||'';if(!html){return '';}
   // Too large to parse in the page's time: returned whole, the size check refuses it.
   if(html.length>4*PASTE_LIMIT){return html;}
   const parsed=new win.DOMParser().parseFromString(html,'text/html');for(const node of parsed.querySelectorAll('script,style,template,noscript')){node.remove();}
   return parsed.body?.textContent||'';
  }
  // A drag that started in the page may end without its `dragend` (dropped in another window, the
  // page removed the source): the pointer coming back up or the drag leaving the window ends it too.
  function dragState(event){
   if(event.type==='dragstart'){draggingInside=true;return true;}
   if(event.type==='dragend'||event.type==='pointerup'||(event.type==='dragleave'&&!event.relatedTarget)){draggingInside=false;return true;}
   // After this drop's own `beforeinput`, which the browser fires during the drop.
   if(event.type==='drop'&&draggingInside){win.setTimeout(()=>{draggingInside=false;},0);}
   return false;
  }
  async function paste(event){
   if(!event.isTrusted||dragState(event)){return;}
   const transfer=transferOf(event);
   if(transfer===undefined||transfer?.files?.length||(event.type!=='paste'&&draggingInside)){return;}
   // A password is never sent for inspection: it is not text the person composes for the provider.
   const target=event.target?.nodeType===1?event.target:event.target?.parentElement;if(!target||target.closest('input[type="password"]')){return;}
   // Without masking the paste goes to the page untouched, but it still opens the exchange: the page may
   // keep it as a chip and send it with an empty draft (real campaign 0.7.9, Claude), as under masking below.
   if(!masking()){if(!overlay?.contains(target)&&composerField(target)&&(typeof event.data==='string'&&event.data||[...(transfer?.types||[])].some(type=>type!=='Files'))){draftCorrelation=draftCorrelation||win.crypto.randomUUID();if(event.type==='paste'||event.type==='drop'){rememberPaste(pastedText(transfer));}}return;}
   // Aimed at the open dialog: no page handler gets it, and the dialog stays.
   if(overlay?.contains(target)){stop(event);return;}
   if(!composerField(target)){return;}
   const text=pastedText(transfer)||(typeof event.data==='string'?event.data:'');
   if(!text){
    // Content without readable text (RTF alone, a link list, an application type) cannot be inspected.
    if([...(transfer?.types||[])].some(type=>type!=='Files')){stop(event);notice('Collage refusé','Ce presse-papiers ne contient aucun texte que le contrôle local peut lire. Collez le contenu en texte brut.');}
    return;
   }
   stop(event);
   if(pasting){notice('Collage refusé','Un collage est déjà en cours de contrôle. Réessayez quand il sera terminé.');return;}
   const selection=win.getSelection?.(),range=selection?.rangeCount?selection.getRangeAt(0).cloneRange():null,url=location.href;
   const bytes=encoder.encode(text).length;
   if(bytes>PASTE_LIMIT){notice('Collage refusé','Le texte collé dépasse la limite du contrôle local. Collez-le en plusieurs fois.');return;}
   // A long paste takes several inspections: say so rather than leave the editor silent.
   let waiting=null,answer;pasting=true;
   const timer=win.setTimeout(()=>{if(!overlay){notice('Collage en cours de contrôle','Le texte collé est contrôlé localement avant d’être inséré.');waiting=overlay;}},400);
   try{answer=await message({type:'paste',text},8000*Math.ceil((bytes+1)/32768));}finally{win.clearTimeout(timer);pasting=false;}
   // Closing the waiting notice cancels the paste; another notice replacing it does not.
   if(waiting){if(dismissed===waiting){return;}if(overlay===waiting){close();}}
   const here=()=>!disposed&&location.href===url&&target.isConnected&&target.ownerDocument===document;
   if(!here()){return;}
   if(!answer?.ok){notice('Collage refusé',answer?.reason||'Connectez l’agent local puis réessayez.');return;}
   if(!['observe','review','block','redirect'].includes(answer.action)||typeof answer.text!=='string'){notice('Collage refusé','Réponse de contrôle non valide.');return;}
   const labels=Array.isArray(answer.labels)?answer.labels:[];
   if(answer.action==='block'){onBlockedInspection(answer,text,labels,'Collage refusé');return;}
   if(answer.action==='redirect'){onRedirectInspection(answer,text,labels);return;}
   // The worker approves the paste for the network guard only now, once the person confirmed it.
   const put=async()=>{
    if(!here()){return;}
    if(answer.confirmation===true&&!(await acknowledgeWarning(answer))){notice('Collage refusé','La confirmation a expiré. Réessayez.');return;}
    if(!here())return;
    if(typeof answer.token==='string'){
     const confirmed=await message({type:'paste-confirm',token:answer.token});
     if(!confirmed?.ok){notice('Collage refusé',confirmed?.reason||'Le texte contrôlé n’a pas pu être inséré.');return;}
     if(!here()){return;}
    }
    if(!(await A.insert(target,answer.text,range))){notice('Collage refusé','Le texte contrôlé n’a pas pu être inséré.');return;}
    rememberPaste(answer.text);
    // The page may keep it as a chip or an attachment, out of the draft: a send with an empty draft
    // is then still held, inspected and recorded, as for a file (real campaign 0.7.8).
    draftCorrelation=draftCorrelation||win.crypto.randomUUID();
   };
   if(answer.confirmation===true){notice('Confirmation requise',answer.reason||'Vérifiez cet envoi avant de confirmer.',answer.text,put,'Valider et coller',()=>cancelWarning(answer));}
   else if(answer.action==='review'||answer.text!==text.replaceAll(/\r\n?/g,'\n')){notice('Informations confidentielles','Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.',answer.text,put,'Valider et coller');}
   else {await put();}
  }
  const THINKING_WAITS=50,thinking=text=>text.length<=64&&/(?:…|\.{3})\s*$/.test(text);
  // claude.ai renders one answer turn as several rows (a file it read, then its text), each a response node
  // sharing `data-turn-key`, the streaming flag on the first only (its bundle, real campaign 0.7.10): one answer.
  // Indexed once per pass: a long conversation holds hundreds of rows, rescanned while an answer streams.
  function turns(){const rows=new Map();for(const row of document.querySelectorAll(adapter.response)){const key=row.getAttribute('data-turn-key');if(key&&!row.querySelector(adapter.response)){if(!rows.has(key)){rows.set(key,[]);}rows.get(key).push(row);}}return rows;}
  // A row without a key (every other provider) is its own turn: no rescan of the page for it.
  // Out of a pass, only the rows of that key are checked: many pending keys must not rescan every row each.
  const sameTurn=key=>[...document.querySelectorAll('[data-turn-key]')].filter(row=>row.getAttribute('data-turn-key')===key&&row.matches(adapter.response)&&!row.querySelector(adapter.response));
  const turn=(node,rows)=>{const key=node.getAttribute?.('data-turn-key'),list=key&&(rows?rows.get(key):sameTurn(key));return list?.length?list:[node];};
  const answerOf=(node,rows)=>turn(node,rows).map(A.answer).filter(Boolean).join('\n\n');
  // Any row of the turn still streaming holds it: the flag may sit on a later row than the first.
  const busy=node=>turn(node).some(row=>A.responseBusy(adapter,row,document));
  function responses(nodes){if(!correlation||!policy?.config.collection.enabled){return;}
   const rows=turns(),leads=new Set();
   for(const found of nodes||document.querySelectorAll(adapter.response)){
    // One answer can match twice (signed-out ChatGPT: an outer message and its text): the innermost counts.
    if(found.querySelector(adapter.response)){continue;}
    const node=turn(found,rows)[0];if(leads.has(node)){continue;}leads.add(node);
    const text=answerOf(node,rows);if(knownResponses.get(node)===text||deliveredResponses.has(text)||!text.trim()||!withinLimit(text)){continue;}
    const existing=responseTimers.get(node);if(existing?.text===text&&existing.id===correlation){continue;}
    if(existing){win.clearTimeout(existing.timer);}
    const entry={text,id:correlation,delivery_id:win.crypto.randomUUID(),retries:0,waits:0,timer:null};responseTimers.set(node,entry);
    const collect=async()=>{
     if(disposed||!node.isConnected||entry.id!==correlation&&!entry.final||responseTimers.get(node)!==entry){return;}
      if(answerOf(node)!==entry.text){responseTimers.delete(node);responses([node]);return;}
     // A short text ending in an ellipsis is a thinking placeholder ("Réflexion…", real campaign 0.7.6),
     // whatever the interface language: waited out, up to THINKING_WAITS checks, then taken as it is.
     if(busy(node)||thinking(entry.text)&&!entry.final&&++entry.waits<=THINKING_WAITS){entry.timer=win.setTimeout(collect,1200);return;}
     const inspectedPolicy=policyState(),inspected=await message({type:'inspect',text:entry.text,upload:false,observation:true});
     if(disposed||entry.id!==correlation&&!entry.final||responseTimers.get(node)!==entry){return;}
     if(answerOf(node)!==entry.text||busy(node)||inspectedPolicy!==policyState()){responseTimers.delete(node);responses();return;}
     // A copy of an answer delivered meanwhile under another node is not a second answer.
     if(deliveredResponses.has(entry.text)){responseTimers.delete(node);return;}
     let delivered=false;
     if(inspected.ok&&typeof inspected.text==='string'&&withinLimit(inspected.text)){delivered=await emit('response',inspected.text,'observed',inspected.labels||[],entry.id,entry.delivery_id);}
     if(delivered){knownResponses.set(node,entry.text);deliveredResponses.add(entry.text);if(deliveredResponses.size>DELIVERED_RESPONSES){deliveredResponses.delete(deliveredResponses.values().next().value);}responseTimers.delete(node);}
     else if(++entry.retries<3){entry.timer=win.setTimeout(collect,1200);}
     else {responseTimers.delete(node);}
    };
    entry.collect=collect;entry.timer=win.setTimeout(collect,1200);
   }
  }
  function blocked(message){
   if(message?.type!=='model-blocked'){return;}
   attempt++;correlation=null;
   const denied=message.reason==='model_denied';
   // A send the worker cancelled for want of a local validation (no approval, policy
   // unavailable) says nothing about a model, even when no model rule exists.
   if(message.reason==='control_unavailable'){
    notice('Envoi bloqué',t('Cet envoi n’a pas été validé par le contrôle local. Renvoyez-le depuis la zone de saisie. Politique')+' '+(message.revision??t('indisponible'))+'.');
    return;
   }
   if(document.documentElement.lang.startsWith('en')){
    const reason=denied?'This model is forbidden.':'The requested model or transport cannot be verified.';
    notice('Request blocked','Model: '+(message.model||'unknown')+'. Policy '+(message.revision??'unavailable')+'. '+reason);
    return;
   }
   const reason=denied?'Ce modèle est interdit.':'Le modèle demandé ou le transport ne peut pas être vérifié.';
   notice('Envoi bloqué','Modèle : '+(message.model||'indéterminé')+'. Politique '+(message.revision??'indisponible')+'. '+reason);
  }
  api?.runtime?.onMessage?.addListener(blocked);
  api?.runtime?.onMessage?.addListener(receipt);
  function listen(type,fn){document.addEventListener(type,fn,true);listeners.push([type,fn]);}
  for(const type of ['submit','click','keydown']){listen(type,handle);}for(const type of ['input','change','drop','paste']){listen(type,upload);}listen('input',event=>{if(!event.target?.matches?.('input[type="file"]')){draftEpoch++;}});
  // On the window, ahead of every handler the page puts on the document or its editor.
  const PASTE_EVENTS=['paste','drop','beforeinput','dragstart','dragend','dragleave','pointerup'];
  for(const type of PASTE_EVENTS){win.addEventListener(type,paste,true);}
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
  const observer=new win.MutationObserver(observeResponses);observer.observe(document,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:['data-is-streaming','aria-busy','data-message-streaming']});
  const navTimer=win.setInterval(navigation,1000),policyTimer=win.setInterval(refresh,30000);void refresh();
  return {handle,upload,paste,refresh,navigation,dispose(){for(const type of PASTE_EVENTS){win.removeEventListener(type,paste,true);}receipts.length=0;chipTexts.length=0;api?.runtime?.onMessage?.removeListener(receipt);api?.runtime?.onMessage?.removeListener(blocked);disposed=true;close();observer.disconnect();win.clearInterval(navTimer);win.clearInterval(policyTimer);for(const [type,fn]of listeners){document.removeEventListener(type,fn,true);}resetResponses();}};
 }
 globalThis.MilvagoCapture={start};
 if(api&&globalThis.document){void (async()=>{globalThis.__milvagoCapture?.dispose?.();globalThis.__milvagoCapture=true;try{const reply=await api.runtime.sendMessage({type:'catalog'});A.applyCatalog(reply?.catalog);}catch{}const running=start(document,location,message=>api.runtime.sendMessage(message));globalThis.__milvagoCapture=running||false;})();}
})();
