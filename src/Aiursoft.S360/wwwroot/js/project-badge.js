document.querySelectorAll('.s360-badge-generator').forEach(generator => {
    const button = generator.querySelector('[data-copy-badge]');
    const markdown = generator.querySelector('textarea');
    const status = generator.querySelector('[data-badge-copy-status]');
    const text = (key, fallback) => generator.querySelector(`[data-badge-localization] [data-key="${key}"]`)?.textContent || fallback;
    button.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(markdown.value);
            status.textContent = text('copied', 'Copied!');
        } catch {
            markdown.focus();
            markdown.select();
            status.textContent = text('copyFailed', 'Select and copy the Markdown above.');
        }
    });
});
