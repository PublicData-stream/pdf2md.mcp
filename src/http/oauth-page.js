'use strict';
// Copy buttons for the OAuth pages. Buttons stay hidden without JavaScript.
async function copyField(button) {
  const field = document.getElementById(button.dataset.copy);
  if (!field || !field.value) {
    return;
  }
  try {
    await navigator.clipboard.writeText(field.value);
  } catch {
    field.focus();
    field.select();
    document.execCommand('copy');
  }
  button.dataset.copied = '';
  button.textContent = 'Copied';
  setTimeout(() => {
    delete button.dataset.copied;
    button.textContent = 'Copy';
  }, 2000);
}
for (const button of document.querySelectorAll('button[data-copy]')) {
  button.hidden = false;
  button.addEventListener('click', () => copyField(button));
}
