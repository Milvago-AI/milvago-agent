const api=globalThis.browser||globalThis.chrome;
const label=document.querySelector('#status');
const messages={
 fr:{unavailable:'Contrôle local indisponible. Les services IA couverts sont bloqués.',expired:'La validation locale a expiré. Actualisez pour vérifier la protection.',checking:'Vérification du contrôle local…',connected:'Agent local connecté.',offline:'Agent local actif, serveur distant indisponible.',content:'Contrôle sélectif du contenu indisponible : les transmissions non vérifiables sont bloquées.',managed:'Une installation administrée avec les permissions de blocage est nécessaire.',transport:'Les transports web de ce service ne sont pas encore qualifiés.',model:'Les transports sans contrôle garanti des modèles sont bloqués.',grace:'Tolérance active : {0} s restantes. Le service Update contrôle les envois.',ended:'Tolérance expirée. Les services IA couverts sont bloqués.',unmanaged:'Installation non gérée — protection dégradée.',seal:'Le verrouillage réseau de secours a échoué : la protection sans agent est incomplète.'},
 en:{unavailable:'Local control unavailable. Covered AI services are blocked.',expired:'Local validation expired. Refresh to check protection.',checking:'Checking local control…',connected:'Local agent connected.',offline:'Local agent active, remote server unavailable.',content:'Selective content control unavailable: transmissions that cannot be verified are blocked.',managed:'A managed installation with blocking permissions is required.',transport:'This service’s web transports have not been qualified yet.',model:'Transports without verified model control are blocked.',grace:'Grace period: {0} s remaining. The Update service controls submissions.',ended:'Grace period expired. Covered AI services are blocked.',unmanaged:'Unmanaged installation — degraded protection.',seal:'The fallback network seal failed: protection without the agent is incomplete.'},
 es:{unavailable:'Control local no disponible. Los servicios de IA cubiertos están bloqueados.',expired:'La validación local ha caducado. Actualiza para comprobar la protección.',checking:'Comprobando el control local…',connected:'Agente local conectado.',offline:'Agente local activo, servidor remoto no disponible.',content:'Control selectivo del contenido no disponible: se bloquean las transmisiones que no se pueden verificar.',managed:'Se requiere una instalación administrada con permisos de bloqueo.',transport:'Los transportes web de este servicio aún no se han validado.',model:'Se bloquean los transportes sin control de modelos verificado.',grace:'Periodo de tolerancia: quedan {0} s. El servicio Update controla los envíos.',ended:'Periodo de tolerancia agotado. Los servicios de IA cubiertos están bloqueados.',unmanaged:'Instalación no administrada — protección degradada.',seal:'El sellado de red de respaldo ha fallado: la protección sin el agente es incompleta.'},
 'pt-BR':{unavailable:'Controle local indisponível. Os serviços de IA cobertos estão bloqueados.',expired:'A validação local expirou. Atualize para verificar a proteção.',checking:'Verificando o controle local…',connected:'Agente local conectado.',offline:'Agente local ativo, servidor remoto indisponível.',content:'Controle seletivo de conteúdo indisponível: transmissões que não podem ser verificadas são bloqueadas.',managed:'É necessária uma instalação gerenciada com permissões de bloqueio.',transport:'Os transportes web deste serviço ainda não foram validados.',model:'Transportes sem controle de modelos verificado são bloqueados.',grace:'Período de tolerância: restam {0} s. O serviço Update controla os envios.',ended:'Período de tolerância expirado. Os serviços de IA cobertos estão bloqueados.',unmanaged:'Instalação não gerenciada — proteção degradada.',seal:'O selo de rede de contingência falhou: a proteção sem o agente está incompleta.'}
};
const preferred=(globalThis.navigator?.language||'fr').toLowerCase();
const language=preferred.startsWith('pt')?'pt-BR':preferred.startsWith('en')?'en':preferred.startsWith('es')?'es':'fr';
document.documentElement.lang=language;
const t=key=>messages[language][key];
const copy={"fr":{"title":"Protection navigateur","refresh":"Actualiser la politique","scope":"Les neuf fournisseurs disposent d’adaptateurs. Leur qualification complète est en cours. Un contrôle indisponible bloque les transmissions concernées. Un événement observé ne prouve pas sa réception par le fournisseur.","usage":"Le texte est contrôlé dans l’agent local. Sa conservation dépend de la politique de votre organisation. Un envoi autorisé reprend automatiquement après validation. Vous pouvez annuler la relecture du texte masqué."},"en":{"title":"Browser protection","refresh":"Refresh policy","scope":"Adapters are available for nine providers. Full qualification is in progress. Unavailable controls block the affected transmissions. An observed event does not prove receipt by the provider.","usage":"Text is checked by the local agent. Your organization’s policy determines whether it is retained. An allowed submission resumes automatically after validation. You can cancel the masked text review."},"es":{"title":"Protección del navegador","refresh":"Actualizar la política","scope":"Hay adaptadores para nueve proveedores. La validación completa está en curso. Los controles no disponibles bloquean las transmisiones afectadas. Un evento observado no demuestra su recepción por el proveedor.","usage":"El agente local comprueba el texto. La política de tu organización determina si se conserva. Un envío permitido se reanuda automáticamente tras la validación. Puedes cancelar la revisión del texto enmascarado."},"pt-BR":{"title":"Proteção do navegador","refresh":"Atualizar a política","scope":"Há adaptadores para nove provedores. A validação completa está em andamento. Controles indisponíveis bloqueiam as transmissões afetadas. Um evento observado não comprova o recebimento pelo provedor.","usage":"O agente local verifica o texto. A política da sua organização determina se ele é armazenado. Um envio permitido é retomado automaticamente após a validação. Você pode cancelar a revisão do texto mascarado."}};
for(const key of ['title','refresh','scope','usage']){document.querySelector('#'+key).textContent=copy[language][key];}
function describe(status){
 if(!status?.connected){return t('unavailable');}
 const elapsed=Date.now()-Date.parse(status.updated_at),expiry=Date.parse(status.expires_at);
 if(!Number.isFinite(elapsed)||!Number.isFinite(expiry)||elapsed<0||Date.now()>=expiry){return t('expired');}
 let text;
 if(status.mode==='grace'){
  const seconds=Math.ceil(Math.max(0,(status.remaining_ms||0)-elapsed)/1000);
  text=seconds>0?t('grace').replace('{0}',seconds):t('ended');
 }else {text=t(status.online?'connected':'offline');}
 if(status.managed===false){text+=' '+t('unmanaged');}
 if(status.content_control==='unavailable'){text+=' '+t('content')+' '+t(status.content_control_reason==='managed_extension_required'?'managed':'transport');}
 if(status.model_control==='unavailable'){text+=' '+t('model');}
 return text;
}
// `seal_failed` is set by the worker when the DNR fail-closed sealing fails and
// cleared when it succeeds or when a refresh replaces the rules; without this
// flag, the failure stayed invisible to the user.
async function show(){
 const {status,seal_failed}=await api.storage.local.get(['status','seal_failed']);
 label.textContent=describe(status)+(seal_failed===true?' '+t('seal'):'');
}
async function refresh(){label.textContent=t('checking');try{await api.runtime.sendMessage({type:'refresh'});await show();}catch{label.textContent=t('unavailable');}}
document.querySelector('#refresh').addEventListener('click',refresh);
setInterval(()=>void show(),1000);
void refresh();
