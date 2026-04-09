function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    alert('Private key copied. Store it safely.');
  }).catch(() => {
    alert('Copy failed. Please copy manually.');
  });
}
