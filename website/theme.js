(() => {
  const root = document.documentElement;
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = null;
  try { preference = localStorage.getItem('vault-theme'); } catch {}
  const requested = new URLSearchParams(window.location.search).get('theme');
  if (requested === 'light' || requested === 'dark') preference = requested;
  if (!['light', 'dark'].includes(preference)) preference = null;
  function apply(theme) {
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]').content = theme === 'dark' ? '#111629' : '#ffffff';
  }
  apply(preference || (system.matches ? 'dark' : 'light'));
  window.vaultTheme = {
    get: () => root.dataset.theme,
    set(theme) {
      if (!['light', 'dark'].includes(theme)) return;
      preference = theme;
      try { localStorage.setItem('vault-theme', theme); } catch {}
      // Keep preview URLs in sync, so a refresh preserves a manual choice.
      const url = new URL(window.location.href);
      if (url.searchParams.has('theme')) {
        url.searchParams.set('theme', theme);
        window.history.replaceState(null, '', url);
      }
      apply(theme);
      window.dispatchEvent(new Event('vault-theme-change'));
    }
  };
  system.addEventListener('change', event => {
    if (preference) return;
    apply(event.matches ? 'dark' : 'light');
    window.dispatchEvent(new Event('vault-theme-change'));
  });
})();
