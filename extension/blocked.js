// The notice a blocked service's page is replaced with: the browser's own error page said
// nothing about why. The service name comes from the URL and is only ever shown as text.
const TEXT={fr:['Service bloqué','Ce service est bloqué par votre organisation.'],en:['Service blocked','This service is blocked by your organization.'],es:['Servicio bloqueado','Su organización bloquea este servicio.'],pt:['Serviço bloqueado','Este serviço é bloqueado pela sua organização.']};
const language=(navigator.language||'fr').slice(0,2).toLowerCase(),[title,detail]=TEXT[language]||TEXT.fr;
document.documentElement.lang=language in TEXT?language:'fr';document.title=title;
document.getElementById('title').textContent=title;document.getElementById('detail').textContent=detail;
document.getElementById('service').textContent=(new URLSearchParams(location.search).get('service')||'').slice(0,253);
