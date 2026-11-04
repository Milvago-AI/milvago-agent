// Apply the extension's explicit choice before styles can paint. System mode
// stays a CSS media query, so an OS change is reflected without a reload.
(() => {
  const valid = value => ['dark', 'light'].includes(value);
  const apply = value => {
    if (valid(value)) { document.documentElement.dataset.theme = value; }
    else { delete document.documentElement.dataset.theme; }
  };
  try { apply(localStorage.getItem('milvago.theme')); } catch { apply(null); }
  const locale = (navigator.language || 'en').toLowerCase();
  const language = locale.startsWith('fr') ? 'fr' : locale.startsWith('es') ? 'es' : locale.startsWith('pt') ? 'pt-BR' : 'en';
  const labels = {
    en: ['Appearance', 'System', 'Dark', 'Light'],
    fr: ['Apparence', 'Système', 'Sombre', 'Clair'],
    es: ['Apariencia', 'Sistema', 'Oscuro', 'Claro'],
    'pt-BR': ['Aparência', 'Sistema', 'Escuro', 'Claro'],
  }[language];
  document.addEventListener('DOMContentLoaded', () => {
    const select = document.getElementById('appearance');
    if (!select) { return; }
    document.getElementById('appearance-label').textContent = labels[0];
    [...select.options].forEach((option, index) => { option.textContent = labels[index + 1]; });
    select.value = document.documentElement.dataset.theme || 'system';
    select.addEventListener('change', () => {
      const value = valid(select.value) ? select.value : 'system';
      apply(value);
      try { localStorage.setItem('milvago.theme', value); } catch { /* Ephemeral appearance still works. */ }
      const api = globalThis.browser || globalThis.chrome;
      try { void api?.storage?.local?.set({ 'milvago.theme': value })?.catch(() => {}); } catch { /* Cosmetic preference only. */ }
    });
  }, { once: true });
})();
