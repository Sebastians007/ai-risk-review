/* Only a non-sensitive appearance preference is persisted. Cookies span local ports. */
(() => {
  const key = 'ai-risk-review-appearance';
  const choices = ['system', 'light', 'dark'];
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try {
    const cookie = document.cookie.split(';').map(value => value.trim()).find(value => value.startsWith(key + '='));
    const saved = cookie ? decodeURIComponent(cookie.slice(key.length + 1)) : 'system';
    if (choices.includes(saved)) preference = saved;
  } catch { /* Storage restrictions leave the system default available. */ }
  function apply() {
    document.documentElement.dataset.theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
  }
  window.ReviewTheme = {
    get preference() { return preference; },
    set(value) {
      if (!choices.includes(value)) return;
      preference = value;
      try { document.cookie = key + '=' + value + '; Max-Age=31536000; Path=/; SameSite=Strict'; } catch { /* In-memory fallback. */ }
      apply();
    }
  };
  media.addEventListener('change', () => { if (preference === 'system') apply(); });
  apply();
})();
