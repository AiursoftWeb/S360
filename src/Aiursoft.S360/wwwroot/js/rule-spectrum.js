(() => {
    const roots = document.querySelectorAll('[data-rule-spectrum="true"]');
    if (!roots.length) return;

    roots.forEach((root) => {
        const filterButtons = Array.from(root.querySelectorAll('[data-spectrum-filter]'));
        const segments = Array.from(root.querySelectorAll('[data-spectrum-segment]'));
        const cards = Array.from(root.querySelectorAll('[data-spectrum-card]'));

        const applyFilter = (status) => {
            filterButtons.forEach((btn) => {
                const active = btn.getAttribute('data-spectrum-filter') === status;
                btn.setAttribute('aria-pressed', active ? 'true' : 'false');
                btn.classList.toggle('active', active);
                if (btn.getAttribute('data-spectrum-filter') === 'all') {
                    btn.classList.toggle('btn-primary', active);
                    btn.classList.toggle('btn-outline-primary', !active);
                }
            });

            cards.forEach((card) => {
                const match = status === 'all' || card.getAttribute('data-spectrum-status') === status;
                card.hidden = !match;
            });

            segments.forEach((seg) => {
                const match = status === 'all' || seg.getAttribute('data-spectrum-status') === status;
                seg.classList.toggle('is-dimmed', !match);
            });
        };

        filterButtons.forEach((btn) => {
            btn.addEventListener('click', () => {
                const status = btn.getAttribute('data-spectrum-filter') || 'all';
                applyFilter(status);
            });
        });

        segments.forEach((seg) => {
            seg.addEventListener('click', () => {
                const version = seg.getAttribute('data-spectrum-segment');
                if (!version) return;
                const targetCard = cards.find((c) => c.getAttribute('data-spectrum-card') === version);
                if (!targetCard) return;

                if (targetCard.hidden) {
                    applyFilter('all');
                }

                segments.forEach((s) => s.classList.toggle('is-selected', s === seg));
                cards.forEach((c) => c.classList.toggle('is-highlighted', c === targetCard));

                const details = targetCard.querySelector('details.s360-spectrum-evidence');
                if (details) details.open = true;

                targetCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            });
        });
    });
})();
