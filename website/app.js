(() => {
  const button = document.getElementById('language');
  const copy = document.getElementById('copy');
  const status = document.getElementById('copy-status');
  const themeButton = document.getElementById('theme-toggle');
  const themeLabel = document.getElementById('theme-label');
  function updateThemeControl() {
    const dark = window.vaultTheme?.get() === 'dark';
    themeLabel.textContent = dark ? 'Light' : 'Dark';
    const label = language === 'zh'
      ? (dark ? '切换浅色风格' : '切换深色风格')
      : (dark ? 'Switch to light theme' : 'Switch to dark theme');
    themeButton.setAttribute('aria-label', label);
    themeButton.title = label;
  }
  themeButton.addEventListener('click', () => {
    window.vaultTheme.set(window.vaultTheme.get() === 'dark' ? 'light' : 'dark');
  });
  window.addEventListener('vault-theme-change', updateThemeControl);
  let language = 'zh';
  try { language = localStorage.getItem('vault-language') || (navigator.language.startsWith('zh') ? 'zh' : 'en'); } catch {}
  if (!['zh', 'en'].includes(language)) language = 'zh';
  function renderDownloads() {
    const release = window.vaultRelease || { assets: {}, url: 'https://github.com/DigholeNet/vault/releases' };
    const labels = language === 'zh'
      ? { android: '下载 APK', macos: '下载 macOS ZIP', 'edge-amd64': '下载 edge · amd64', 'edge-arm64': '下载 edge · arm64', 'supernode-amd64': '下载 supernode · amd64', 'supernode-arm64': '下载 supernode · arm64' }
      : { android: 'Download APK', macos: 'Download macOS ZIP', 'edge-amd64': 'Download edge · amd64', 'edge-arm64': 'Download edge · arm64', 'supernode-amd64': 'Download supernode · amd64', 'supernode-arm64': 'Download supernode · arm64' };
    const fallbackLabels = {
      'edge-amd64': 'edge · amd64',
      'edge-arm64': 'edge · arm64',
      'supernode-amd64': 'supernode · amd64',
      'supernode-arm64': 'supernode · arm64',
    };
    document.querySelectorAll('[data-release-asset]').forEach(link => {
      const key = link.dataset.releaseAsset;
      const asset = release.assets[key];
      link.href = asset || release.url;
      const label = link.querySelector('.download-label');
      if (label) label.textContent = asset ? labels[key] : (fallbackLabels[key] || (language === 'zh' ? '查看发布页' : 'View releases'));
    });
    document.getElementById('release-notes').href = release.url;
    if (release.version) {
      document.getElementById('release-status').textContent = release.version + ' · ' + release.published;
      document.getElementById('release-description').textContent = language === 'zh'
        ? '以下入口来自最新正式 Release。若某个平台没有对应安装包，请查看发布说明或从源码构建。'
        : 'These links come from the latest stable release. If an asset is unavailable for your platform, check release notes or build from source.';
    }
    document.getElementById('android-qr-caption').textContent = release.assets.android
      ? (language === 'zh' ? '扫码下载同一 APK' : 'Scan to download the same APK')
      : (language === 'zh' ? '扫码查看发布页' : 'Scan to view releases');
  }
  function render() {
    updateThemeControl();
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
    document.querySelectorAll('[data-zh][data-en]').forEach(element => {
      const parts = element.dataset[language].split('<br>');
      element.replaceChildren();
      parts.forEach((part, index) => {
        if (index) element.append(document.createElement('br'));
        element.append(document.createTextNode(part));
      });
    });
    renderDownloads();
    button.textContent = language === 'zh' ? 'EN ↗' : '中文 ↗';
    button.setAttribute('aria-label', language === 'zh' ? 'Switch to English' : '切换到中文');
    document.title = language === 'zh' ? 'Vault — 连接，由你掌控。' : 'Vault — Your network. Your rules.';
    document.querySelector('meta[name="description"]').content = language === 'zh'
      ? 'Vault 是开源、跨平台、自托管的 VPN，以共享 Rust 核心连接 Apple、Android 与 Linux。'
      : 'Vault is an open-source, cross-platform, self-hosted VPN connecting Apple, Android and Linux with one Rust core.';
  }
  button.addEventListener('click', () => {
    language = language === 'zh' ? 'en' : 'zh';
    try { localStorage.setItem('vault-language', language); } catch {}
    render();
  });
  copy.addEventListener('click', async () => {
    const command = 'git clone https://github.com/DigholeNet/vault.git';
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(command);
      copy.textContent = language === 'zh' ? '已复制 ✓' : 'Copied ✓';
      status.textContent = copy.textContent;
    } catch {
      const range = document.createRange();
      range.selectNodeContents(document.querySelector('.clone code'));
      const selection = window.getSelection();
      selection.removeAllRanges(); selection.addRange(range);
      copy.textContent = language === 'zh' ? '请手动复制' : 'Copy selected text';
      status.textContent = copy.textContent;
    }
    setTimeout(() => { copy.textContent = copy.dataset[language]; }, 2400);
  });
  const navigation = [...document.querySelectorAll('header nav a[href^="#"]')];
  const chapters = navigation.map(link => document.querySelector(link.getAttribute('href'))).filter(Boolean);
  function highlight(id) {
    navigation.forEach(link => {
      const active = link.getAttribute('href') === '#' + id;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
  }
  let framePending = false;
  let clickedChapter = null;
  let releaseTimer;
  function updateNavigation() {
    if (clickedChapter) return;
    const boundary = document.querySelector('header').getBoundingClientRect().bottom + 60;
    let current = chapters[0];
    for (const chapter of chapters) {
      if (chapter.getBoundingClientRect().top <= boundary) current = chapter;
    }
    if (current) highlight(current.id);
  }
  navigation.forEach(link => link.addEventListener('click', () => {
    clickedChapter = link.getAttribute('href').slice(1);
    highlight(clickedChapter);
    clearTimeout(releaseTimer);
    releaseTimer = setTimeout(() => { clickedChapter = null; updateNavigation(); }, 1000);
  }));
  window.addEventListener('scroll', () => {
    if (framePending) return;
    framePending = true;
    requestAnimationFrame(() => { framePending = false; updateNavigation(); });
  }, { passive: true });
  window.addEventListener('resize', updateNavigation);
  window.addEventListener('hashchange', () => {
    if (!clickedChapter) updateNavigation();
  });
  render();
  updateNavigation();
})();
