"use strict";
// Copy buttons for the OAuth pages. Buttons stay hidden without JavaScript.
// `pnpm run build` emits oauth-page.js from oauth-page.ts; edit oauth-page.ts.
const CopiedResetDelay = 2000;
async function CopyField(Button) {
    const Field = document.getElementById(Button.dataset['copy'] ?? '');
    if (!(Field instanceof HTMLInputElement || Field instanceof HTMLTextAreaElement) || !Field.value) {
        return;
    }
    try {
        await navigator.clipboard.writeText(Field.value);
    }
    catch {
        Field.focus();
        Field.select();
        // Fallback for browsers that deny the asynchronous Clipboard API.
        document.execCommand('copy');
    }
    Button.dataset['copied'] = '';
    Button.textContent = 'Copied';
    setTimeout(() => {
        delete Button.dataset['copied'];
        Button.textContent = 'Copy';
    }, CopiedResetDelay);
}
for (const Button of document.querySelectorAll('button[data-copy]')) {
    Button.hidden = false;
    Button.addEventListener('click', () => {
        void CopyField(Button);
    });
}
