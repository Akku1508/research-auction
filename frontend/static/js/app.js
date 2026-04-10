function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.textContent || '';
  navigator.clipboard.writeText(text).then(() => {
    alert('Copied to clipboard.');
  }).catch(() => {
    alert('Copy failed. Please copy manually.');
  });
}

function copyInputValue(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const text = input.value || '';
  navigator.clipboard.writeText(text).then(() => {
    alert('Copied to clipboard.');
  }).catch(() => {
    alert('Copy failed. Please copy manually.');
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
