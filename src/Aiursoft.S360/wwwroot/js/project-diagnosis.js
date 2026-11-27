(() => {
    // 1. Category filter pills inside the project diagnosis panel.
    document.querySelectorAll('.s360-diagnosis-panel').forEach(panel => {
        const buttons = [...panel.querySelectorAll('[data-diagnosis-filter]')];
        const cards = [...panel.querySelectorAll('[data-issue-category]')];
        const emptyNotice = panel.querySelector('[data-diagnosis-empty]');
        if (buttons.length === 0 || cards.length === 0) return;

        buttons.forEach(button => {
            button.addEventListener('click', () => {
                const selected = button.dataset.diagnosisFilter || 'all';
                buttons.forEach(b => b.classList.toggle('active', b === button));
                let visible = 0;
                cards.forEach(card => {
                    const show = selected === 'all' || card.dataset.issueCategory === selected;
                    card.hidden = !show;
                    if (show) visible++;
                });
                if (emptyNotice) emptyNotice.hidden = visible > 0;
            });
        });
    });

    // 2. Live client-side package filter inside the project's full dependency inventory.
    document.querySelectorAll('.s360-project-all-deps').forEach(container => {
        const input = container.querySelector('[data-project-package-filter]');
        const onlyIssues = container.querySelector('[data-project-package-only-issues]');
        const status = container.querySelector('[data-project-package-filter-status]');
        const items = [...container.querySelectorAll('[data-package-search]')];
        if (!input || items.length === 0) return;

        const apply = () => {
            const term = input.value.trim().toLowerCase();
            const issuesOnly = Boolean(onlyIssues?.checked);
            let shown = 0;
            items.forEach(item => {
                const haystack = item.dataset.packageSearch || '';
                const isIssue = item.dataset.packageHasIssue === 'true';
                const matches = (!term || haystack.includes(term)) && (!issuesOnly || isIssue);
                item.hidden = !matches;
                if (matches) shown++;
            });
            if (status) {
                status.textContent = `${shown} / ${items.length}`;
            }
        };

        input.addEventListener('input', apply);
        onlyIssues?.addEventListener('change', apply);
        apply();
    });
})();
