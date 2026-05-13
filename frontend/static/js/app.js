function getToastRack() {
  let rack = document.querySelector('.toast-rack');
  if (!rack) {
    rack = document.createElement('div');
    rack.className = 'toast-rack';
    document.body.appendChild(rack);
  }
  return rack;
}

function showToast(message, isError = false) {
  const toast = document.createElement('div');
  toast.className = `toast${isError ? ' error' : ''}`;
  toast.textContent = message;
  getToastRack().appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, 2200);
}

const THEME_STORAGE_KEY = 'research-auction-theme';
const LIGHT_THEME = 'light';
const DARK_THEME = 'dark';

function getStoredTheme() {
  try {
    const storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    return storedTheme === DARK_THEME ? DARK_THEME : LIGHT_THEME;
  } catch (error) {
    return LIGHT_THEME;
  }
}

function applyTheme(theme) {
  const normalizedTheme = theme === DARK_THEME ? DARK_THEME : LIGHT_THEME;
  document.documentElement.dataset.theme = normalizedTheme;
  document.documentElement.style.colorScheme = normalizedTheme;

  if (document.body) {
    document.body.dataset.theme = normalizedTheme;
  }

  try {
    localStorage.setItem(THEME_STORAGE_KEY, normalizedTheme);
  } catch (error) {
    // Ignore storage failures and keep the current session theme.
  }

  const themeToggle = document.querySelector('[data-theme-toggle]');
  if (!themeToggle) return;

  const isDark = normalizedTheme === DARK_THEME;
  themeToggle.setAttribute('aria-pressed', String(isDark));
  themeToggle.setAttribute('aria-label', isDark ? 'Switch to light theme' : 'Switch to dark theme');

  const label = themeToggle.querySelector('[data-theme-toggle-label]');
  if (label) {
    label.textContent = isDark ? 'Dark' : 'Light';
  }
}

function initializeThemeToggle() {
  applyTheme(document.documentElement.dataset.theme || getStoredTheme());

  const themeToggle = document.querySelector('[data-theme-toggle]');
  if (!themeToggle) return;

  themeToggle.addEventListener('click', () => {
    const nextTheme = document.documentElement.dataset.theme === DARK_THEME ? LIGHT_THEME : DARK_THEME;
    applyTheme(nextTheme);
  });
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard.');
  }).catch(() => {
    showToast('Copy failed. Please copy manually.', true);
  });
}

function copyInputValue(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const text = input.value || '';
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard.');
  }).catch(() => {
    showToast('Copy failed. Please copy manually.', true);
  });
}

function generateRandomness(inputId, previewId) {
  const input = document.getElementById(inputId);
  if (!input) return;

  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const decimal = BigInt(`0x${hex}`).toString(10);
  input.value = decimal;

  if (previewId) {
    const preview = document.getElementById(previewId);
    if (preview) preview.textContent = `Generated r_i: ${decimal}`;
  }
}

function syncAuctionTypeSections(form) {
  const typeSelect = form.querySelector('[data-auction-type-select]');
  if (!typeSelect) return;

  const activeType = typeSelect.value || 'reverse';
  form.querySelectorAll('[data-auction-type-section]').forEach((section) => {
    const sectionType = section.dataset.auctionTypeSection;
    const isActive = sectionType === activeType;
    section.hidden = !isActive;
    section.querySelectorAll('input, select, textarea, button').forEach((field) => {
      if (field === typeSelect) return;
      field.disabled = !isActive;
    });
  });
}

function surfaceFlashMessages() {
  const flashes = Array.from(document.querySelectorAll('.flash'));
  if (!flashes.length) return;

  const flashWrap = flashes[0].closest('.flash-wrap');
  if (flashWrap && typeof flashWrap.scrollIntoView === 'function') {
    flashWrap.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }

  flashes.forEach((flash) => {
    if (
      flash.classList.contains('flash-error') ||
      flash.classList.contains('flash-warning')
    ) {
      showToast(flash.textContent.trim(), true);
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initializeThemeToggle();
  surfaceFlashMessages();

  document.querySelectorAll('form[data-auction-form]').forEach((form) => {
    const typeSelect = form.querySelector('[data-auction-type-select]');
    if (!typeSelect) return;
    const update = () => syncAuctionTypeSections(form);
    typeSelect.addEventListener('change', update);
    update();
  });
});
