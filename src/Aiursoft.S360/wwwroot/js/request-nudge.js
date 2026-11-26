document.querySelectorAll('[data-request-nudge]').forEach(container => {
    const button = container.querySelector('[data-copy-nudge]');
    const messageBox = container.querySelector('[data-nudge-message]');
    const status = container.querySelector('[data-nudge-status]');
    if (!button || !messageBox || !status) return;

    const text = (key, fallback) =>
        container.querySelector(`[data-nudge-localization] [data-key="${key}"]`)?.textContent || fallback;

    button.addEventListener('click', async () => {
        const payload = messageBox.value;
        try {
            await navigator.clipboard.writeText(payload);
            status.textContent = text('copied', 'Approval link and message copied.');
        } catch {
            messageBox.hidden = false;
            messageBox.focus();
            messageBox.select();
            status.textContent = text('copyFailed', 'Select and copy the message below.');
        }
    });
});
