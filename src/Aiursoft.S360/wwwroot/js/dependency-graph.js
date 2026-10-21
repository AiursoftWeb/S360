// Relationships come from the reported restore graph; never infer edges from package names.
const host = document.querySelector('.s360-graph');
if (host) {
    const { solutionView, solutionPaths } = await import(document.getElementById('s360-solution-module').src);
    const find = name => host.querySelector(`.s360-graph-${name}`);
    const text = key => host.querySelector(`[data-key="${key}"]`).textContent;
    const format = (key, ...values) => values.reduce((s, v, i) => s.replace(`{${i}}`, v), text(key));
    const data = JSON.parse(find('data').textContent);
    const graphs = data.Solution ? [solutionView(data.Solution)] : data.Graphs;
    const scope = find('scope'), search = find('search'), depth = find('depth'), risk = find('risk');
    const canvas = find('canvas'), detail = find('detail'), notice = find('notice');
    const stage = find('stage');
    const compact = window.matchMedia('(max-width: 767px)');
    let nodes, parents, distances, roots, selected = '', mermaid, svg, bounds, view, drag;
    let expanded = new Set(), collapsed = new Set(), sequence = 0, timer, rendering = Promise.resolve();
    let suppressClick = false, restoreNotice = '';
    const current = () => graphs[Number(scope.value)];
    const name = node => node.Package ? `${node.Package.Name}@${node.Package.Version}` : node.Label || (node.Kind === 'root' ? current().Project : node.Id);
    const status = node => text(['compliant', 'pending', 'problem'][node.Status]);
    const riskStatus = node => node.Advisories.length ? text('vulnerable') : node.RiskCount ? text('affected') : status(node);
    const level = () => Math.max(1, Math.min(20, Math.floor(Number(depth.value) || 3)));
    const directDependency = node => node.IsDirect ?? distances.get(node.Id) === 1;
    const relation = node => text(directDependency(node) ? 'direct' : distances.has(node.Id) ? 'indirect' : 'unlinked');
    const isOpen = id => !collapsed.has(id) && (expanded.has(id) || distances.get(id) < level());
    const escapeLabel = value => Array.from(value).map(c => /[a-zA-Z0-9 ._/@-]/.test(c) ? c : `#${c.codePointAt(0)};`).join('');
    const element = (tag, value, className) => {
        const el = document.createElement(tag);
        if (value != null) el.textContent = value;
        if (className) el.className = className;
        return el;
    };
    function load() {
        nodes = new Map(current().Nodes.map(n => [n.Id, n]));
        parents = new Map(current().Nodes.map(n => [n.Id, []]));
        for (const node of nodes.values()) for (const child of node.Children) parents.get(child)?.push(node.Id);
        roots = current().RootIds || [current().Nodes.find(n => n.Kind === 'root').Id];
        distances = new Map(roots.map(id => [id, 0]));
        const queue = [...roots];
        for (let i = 0; i < queue.length; i++) for (const child of nodes.get(queue[i]).Children) {
            if (!nodes.has(child) || distances.has(child)) continue;
            distances.set(child, distances.get(queue[i]) + 1);
            queue.push(child);
        }
    }
    function saveView() {
        const url = new URL(location.href);
        const state = { manifest: current().Project, ecosystem: current().Ecosystem, target: current().Target,
            report: current().CheckId, projection: current().IsSolution ? 3 : 1, depth: level(), query: search.value, risk: risk.checked, selected,
            expanded: [...expanded].map(id => current().Nodes.indexOf(nodes.get(id))),
            collapsed: [...collapsed].map(id => current().Nodes.indexOf(nodes.get(id))) };
        url.hash = new URLSearchParams({ tree: JSON.stringify(state) });
        history.replaceState(null, '', url);
    }
    function schedule() {
        const ticket = ++sequence;
        clearTimeout(timer);
        timer = setTimeout(() => {
            // Mermaid renders through a shared document. Serialize renders and discard stale results.
            rendering = rendering.then(() => ticket === sequence ? render(ticket) : undefined).catch(() => {
                if (ticket === sequence) notice.textContent = text('failed');
            });
        }, 120);
        saveView();
    }
    function toggle(id) {
        if (isOpen(id)) { expanded.delete(id); collapsed.add(id); }
        else { collapsed.delete(id); expanded.add(id); }
        selected = id;
        // Explicit expansion returns from path-only filtering to the full graph.
        search.value = ''; risk.checked = false;
        schedule();
    }
    function showDetails() {
        detail.replaceChildren();
        const node = nodes.get(selected);
        detail.hidden = current().IsSolution && !node;
        find('body').classList.toggle('has-selection', !detail.hidden);
        if (!node) { detail.append(element('p', text('select'), 'text-muted')); return; }
        detail.append(element('h4', name(node)));
        if (current().IsSolution && node.Kind === 'project') {
            detail.append(element('p', node.ProjectPath, 'small'));
            if (node.Targets.length) detail.append(element('h5', text('framework')), element('p', node.Targets.join(', '), 'small'));
        } else if (node.RootProjectPath) {
            detail.append(element('h5', text('resolvedFor')), element('p', node.RootProjectPath, 'small'));
            detail.append(element('h5', text('framework')), element('p', node.Target, 'small'));
            if (node.ReferencedTarget) detail.append(element('p', node.ReferencedTarget, 'small'));
        }
        if (node.RiskCount) detail.append(element('p', format('foldedRisk', node.RiskCount), 's360-cve-label'));
        if (node.Package) {
            detail.append(element('p', relation(node), 'small'));
            const riskClass = node.Advisories.length ? 'vulnerable' : node.RiskCount ? 'affected' : node.Status;
            detail.append(element('span', riskStatus(node), `s360-node-status status-${riskClass}`));
            if (node.Reason) {
                detail.append(element('h5', text('policy')), element('p', `${status(node)} · ${node.Reason}`, 'small'));
            }
            for (const advisory of node.Advisories) detail.append(element('span', advisory, 's360-cve-label'));
            detail.append(element('h5', text('source')), element('p', node.Package.Source, 'small'));
        }
        const actions = element('div', null, 's360-graph-actions');
        if (node.RiskCount || node.Advisories.length) {
            const button = element('button', text('vulnerabilityPaths'), 'btn btn-outline-danger btn-sm');
            button.type = 'button';
            button.addEventListener('click', () => { search.value = ''; risk.checked = true; schedule(); });
            actions.append(button);
        }
        if (node.Children.length) {
            const button = element('button', `${text(isOpen(node.Id) ? 'collapse' : 'expand')} (${node.Children.length})`, 'btn btn-outline-primary btn-sm');
            button.type = 'button'; button.addEventListener('click', () => toggle(node.Id)); actions.append(button);
        }
        const path = element('button', text('path'), 'btn btn-outline-secondary btn-sm');
        path.type = 'button';
        path.addEventListener('click', () => { search.value = node.Id; risk.checked = false; schedule(); });
        actions.append(path); detail.append(actions);
        function links(title, ids) {
            if (!ids.length) return;
            detail.append(element('h5', text(title)));
            const list = element('ul');
            for (const id of ids) {
                const target = nodes.get(id);
                if (!target) continue;
                const li = element('li');
                const button = element('button', name(target), 's360-graph-node-link');
                button.type = 'button'; button.addEventListener('click', () => {
                    selected = id; search.value = id; risk.checked = false; schedule();
                });
                li.append(button); list.append(li);
            }
            detail.append(list);
        }
        links('introduced', parents.get(node.Id) || []);
        links('children', node.Children);
        links('usedByFiles', node.UsedBy || []);
        if (node.Package && node.Resolutions?.length) {
            detail.append(element('h5', text('resolvedFor')));
            for (const resolution of node.Resolutions) detail.append(element('p', `${resolution.ProjectPath} · ${resolution.Target}`, 'small'));
        }
        if (node.Package) {
            detail.append(element('h5', text('purpose')));
            for (const purpose of node.Purposes.length ? node.Purposes : [text('noPurpose')]) detail.append(element('p', purpose, 'small'));
            detail.append(element('h5', text('used')));
            for (const project of node.Projects) {
                const a = element('a', project, 's360-graph-project-link');
                const url = new URL(location.href); url.hash = ''; url.search = '';
                url.searchParams.set('tab', 'projects'); url.searchParams.set('project', project);
                url.searchParams.set('scope', new URL(location.href).searchParams.get('scope') || 'baseline');
                a.href = url.href; detail.append(a);
            }
        }
    }
    function markSelection() {
        canvas.querySelectorAll('g.node[data-node]').forEach(el => el.classList.toggle('s360-selected', el.dataset.node === selected));
    }
    async function render(ticket) {
        const focusedNode = canvas.contains(document.activeElement) ? document.activeElement.closest('g.node')?.dataset.node : null;
        const graph = current(), query = search.value.trim().toLowerCase();
        const vulnerable = graph.Nodes.filter(n => n.Package && n.Advisories.length > 0);
        const vulnerableArtifacts = new Set(vulnerable.map(n => n.ArtifactId || n.Id));
        const seeds = graph.Nodes.filter(n => (!query || (nodes.has(search.value.trim()) ? n.Id === search.value.trim() : `${name(n)} ${n.Id} ${n.Advisories.join(' ')}`.toLowerCase().includes(query))) && (!risk.checked || n.Advisories.length));
        const visible = new Set(), edges = []; let limited = false;
        function add(id) {
            if (!nodes.has(id) || visible.has(id)) return false;
            if (visible.size >= 150) { limited = true; return false; }
            visible.add(id); return true;
        }
        if (graph.IsSolution && (query || risk.checked)) {
            const pathEdges = new Map();
            const ordered = [...seeds].sort((a, b) => Number(b.Id === selected) - Number(a.Id === selected));
            for (const seed of ordered) {
                const paths = solutionPaths(graph, new Set([seed.Id]));
                const missing = [...paths.visible].filter(id => !visible.has(id));
                // Keep complete introduction paths; never trim a path halfway to fit the budget.
                const newEdges = paths.edges.filter(edge => !pathEdges.has(JSON.stringify(edge)));
                if (visible.size + missing.length > 150 || pathEdges.size + newEdges.length > 400) { limited = true; continue; }
                for (const id of paths.visible) add(id);
                for (const edge of newEdges) pathEdges.set(JSON.stringify(edge), edge);
            }
            edges.push(...pathEdges.values());
            if (!visible.has(selected)) selected = seeds[0]?.Id || '';
        } else if (query || risk.checked) {
            // A focused node is retained even if it is outside the ordinary depth or node budget.
            const ordered = [...seeds].sort((a, b) => Number(b.Id === selected) - Number(a.Id === selected));
            for (const seed of ordered) {
                const path = new Set(), queue = [seed.Id];
                for (let i = 0; i < queue.length; i++) {
                    const id = queue[i]; if (path.has(id)) continue; path.add(id);
                    queue.push(...(parents.get(id) || []));
                }
                const missing = [...path].filter(id => !visible.has(id));
                if (visible.size + missing.length > 150 && visible.size > 0) { limited = true; continue; }
                for (const id of path) add(id);
            }
            for (const id of visible) for (const child of nodes.get(id).Children) if (visible.has(child)) edges.push([id, child]);
            if (!nodes.has(selected) || !visible.has(selected)) selected = ordered[0]?.Id || '';
        } else {
            const queue = [...roots]; for (const id of roots) add(id);
            for (let i = 0; i < queue.length; i++) {
                const id = queue[i]; if (!isOpen(id)) continue;
                for (const child of nodes.get(id).Children) {
                    if (add(child)) queue.push(child);
                    if (visible.has(child)) edges.push([id, child]);
                }
            }
        }
        const notes = [restoreNotice];
        if (limited || edges.length > 400) notes.push(text('limited'));
        if (query || risk.checked) notes.push(text('pathsNotice'));
        if (distances.size < nodes.size) notes.push(text('unlinkedNotice'));
        notice.textContent = notes.filter(Boolean).join(' ');
        find('summary').textContent = format('visible', visible.size, nodes.size);
        const visibleVulnerable = new Set(vulnerable.filter(n => visible.has(n.Id)).map(n => n.ArtifactId || n.Id));
        find('risk-summary').textContent = vulnerableArtifacts.size ? format('risks', vulnerableArtifacts.size, vulnerableArtifacts.size - visibleVulnerable.size) : text('none');
        find('risk-summary').classList.toggle('has-risk', vulnerable.length > 0);
        find('show-risks').hidden = !vulnerable.length;
        showDetails();
        if (!visible.size) { canvas.replaceChildren(); svg = null; notice.textContent = limited ? text('limited') : text('empty'); return; }
        const ids = new Map([...visible].map((id, i) => [id, `n${i}`]));
        const code = [compact.matches || graph.IsSolution && risk.checked ? 'flowchart TD' : 'flowchart LR',
            'classDef neutral fill:#f1f2f6,stroke:#818b9d,color:#354052',
            'classDef vulnerable fill:#fff0f1,stroke:#cf354c,color:#852036,stroke-width:2px',
            'classDef affected fill:#fff9f0,stroke:#b5893e,color:#4f4432,stroke-width:2px',
            'classDef unverified stroke:#ae7916,stroke-dasharray:4 3'];
        for (const id of visible) {
            const node = nodes.get(id);
            const kind = node.Advisories.length ? 'vulnerable' : node.RiskCount ? 'affected' : 'neutral';
            const lines = !node.Package ? [name(node)] :
                [node.Package.Name, node.Package.Version, node.Advisories[0] || (node.Status !== 0 ? status(node) : '')];
            const label = lines.filter(Boolean).flatMap(line => {
                const shortened = line.length > 100 ? line.slice(0, 97) + '...' : line;
                return [shortened];
            }).map(escapeLabel).join('<br/>');
            code.push(`${ids.get(id)}["${label}"]:::${kind}`);
            if (node.Package && node.Status !== 0 && !node.Advisories.length) code.push(`class ${ids.get(id)} unverified`);
        }
        for (const [from, to] of edges.slice(0, 400)) code.push(`${ids.get(from)} --> ${ids.get(to)}`);
        try {
            mermaid ??= (await import('/node_modules/mermaid/dist/mermaid.esm.mjs')).default;
            mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', theme: 'base', maxTextSize: 250000,
                themeVariables: { fontFamily: 'inherit', fontSize: '14px', lineColor: '#a1adbf' },
                flowchart: { htmlLabels: false, useMaxWidth: false, nodeSpacing: 28, rankSpacing: 55, curve: 'basis' } });
            const result = await mermaid.render(`s360_dependency_${ticket}`, code.join('\n'));
            if (ticket !== sequence) return;
            canvas.innerHTML = result.svg;
            svg = canvas.querySelector('svg');
            const box = svg.viewBox.baseVal;
            bounds = { x: box.x, y: box.y, width: box.width, height: box.height };
            fit();
            const bySvgId = new Map([...ids].map(([id, key]) => [key, id]));
            for (const group of svg.querySelectorAll('g.node')) {
                const id = bySvgId.get(group.id.match(/^flowchart-(n\d+)-/)?.[1]);
                if (!id) continue;
                const node = nodes.get(id);
                group.dataset.node = id; group.setAttribute('tabindex', '0'); group.setAttribute('role', 'button');
                group.setAttribute('aria-label', `${name(node)}${node.Package ? ` · ${relation(node)} · ${riskStatus(node)}` : ''}`);
                const select = () => { selected = id; showDetails(); markSelection(); saveView(); };
                group.addEventListener('click', event => { if (!suppressClick) { event.stopPropagation(); select(); } });
                group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
                if (!node.Children.length) continue;
                const rect = group.querySelector('rect'); if (!rect) continue;
                const b = rect.getBBox(), control = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                control.classList.add('s360-node-toggle'); control.setAttribute('role', 'button'); control.setAttribute('tabindex', '0');
                control.setAttribute('aria-label', `${text(isOpen(id) ? 'collapse' : 'expand')}: ${name(node)}`);
                control.setAttribute('aria-expanded', String(isOpen(id)));
                control.setAttribute('transform', `translate(${b.x + b.width - 4},${b.y + b.height - 4})`);
                const circle = document.createElementNS(control.namespaceURI, 'circle'); circle.setAttribute('r', '12');
                const label = document.createElementNS(control.namespaceURI, 'text'); label.setAttribute('text-anchor', 'middle'); label.setAttribute('dy', '4');
                label.textContent = isOpen(id) ? '−' : `+${node.Children.length}`;
                control.append(circle, label);
                control.addEventListener('click', event => { event.stopPropagation(); if (!suppressClick) toggle(id); });
                control.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); event.stopPropagation(); toggle(id); } });
                group.append(control);
            }
            markSelection();
            if (graph.IsSolution) fit(); else readableView();
            if (focusedNode) [...svg.querySelectorAll('g.node')].find(n => n.dataset.node === focusedNode)?.focus({ preventScroll: true });
        } catch {
            if (ticket === sequence) { canvas.replaceChildren(); svg = null; notice.textContent = text('failed'); }
        }
    }
    function applyView() { if (svg && view) svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.width} ${view.height}`); }
    function fit() {
        if (!svg || !bounds) return;
        const ratio = canvas.clientWidth / canvas.clientHeight;
        const width = Math.max(bounds.width, bounds.height * ratio) * 1.08, height = width / ratio;
        view = { x: bounds.x + (bounds.width - width) / 2, y: bounds.y + (bounds.height - height) / 2, width, height };
        applyView();
    }
    function readableView() {
        fit();
        if (!svg || canvas.clientWidth / view.width >= .7) return;
        const anchor = [...svg.querySelectorAll('g.node')].find(n => n.dataset.node === (selected || roots[0]));
        if (!anchor) return;
        const rect = anchor.getBoundingClientRect();
        const point = new DOMPoint(rect.x + rect.width / 2, rect.y + rect.height / 2).matrixTransform(svg.getScreenCTM().inverse());
        const width = canvas.clientWidth / .85, height = canvas.clientHeight / .85;
        view = { x: point.x - width * (selected ? .5 : .3), y: point.y - height / 2, width, height };
        applyView();
        notice.textContent += ` ${text('readable')}`;
    }
    function zoom(factor) {
        if (!svg || !view) return;
        const width = Math.max(bounds.width / 12, Math.min(bounds.width * 5, view.width * factor));
        const height = view.height * width / view.width;
        view = { x: view.x + (view.width - width) / 2, y: view.y + (view.height - height) / 2, width, height };
        applyView();
    }
    canvas.addEventListener('pointerdown', event => {
        if (!svg || event.button !== 0) return;
        suppressClick = false;
        drag = { id: event.pointerId, x: event.clientX, y: event.clientY, view: { ...view } };
        if (!event.target.closest('.node')) canvas.setPointerCapture(event.pointerId);
    });
    canvas.addEventListener('pointermove', event => {
        if (!drag || drag.id !== event.pointerId) return;
        const dx = event.clientX - drag.x, dy = event.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 4) { suppressClick = true; canvas.setPointerCapture(event.pointerId); }
        view.x = drag.view.x - dx * drag.view.width / canvas.clientWidth;
        view.y = drag.view.y - dy * drag.view.height / canvas.clientHeight;
        applyView();
    });
    const release = () => { drag = null; setTimeout(() => { suppressClick = false; }, 0); };
    canvas.addEventListener('pointerup', release); canvas.addEventListener('pointercancel', release);
    canvas.addEventListener('keydown', event => {
        if (event.target !== canvas || !view) return;
        if (event.key === '+' || event.key === '=') zoom(.8);
        else if (event.key === '-') zoom(1.25);
        else if (event.key === 'ArrowLeft') view.x -= view.width * .1;
        else if (event.key === 'ArrowRight') view.x += view.width * .1;
        else if (event.key === 'ArrowUp') view.y -= view.height * .1;
        else if (event.key === 'ArrowDown') view.y += view.height * .1;
        else return;
        event.preventDefault(); applyView();
    });
    function reset() {
        search.value = ''; risk.checked = false; depth.value = current().IsSolution ? '1' : '3'; selected = '';
        expanded.clear(); collapsed.clear(); restoreNotice = ''; schedule();
    }
    scope.addEventListener('change', () => { load(); reset(); });
    search.addEventListener('input', schedule);
    risk.addEventListener('change', schedule);
    depth.addEventListener('change', () => { depth.value = level(); expanded.clear(); collapsed.clear(); search.value = ''; risk.checked = false; schedule(); });
    find('direct').addEventListener('click', () => { depth.value = '1'; depth.dispatchEvent(new Event('change')); });
    find('reset').addEventListener('click', reset);
    find('show-risks').addEventListener('click', () => { search.value = ''; risk.checked = true; schedule(); });
    find('fit').addEventListener('click', fit);
    find('zoom-in').addEventListener('click', () => zoom(.8));
    find('zoom-out').addEventListener('click', () => zoom(1.25));
    find('fullscreen').addEventListener('click', async () => {
        try { if (document.fullscreenElement === stage) await document.exitFullscreen(); else await stage.requestFullscreen(); }
        catch { /* The browser may not support fullscreen; the diagram stays usable. */ }
    });
    find('share').addEventListener('click', async () => {
        saveView();
        try { await navigator.clipboard.writeText(location.href); notice.textContent = text('copied'); }
        catch { notice.textContent = text('copyFailed'); }
    });
    compact.addEventListener('change', schedule);
    new ResizeObserver(() => fit()).observe(canvas);
    load();
    try {
        const raw = new URLSearchParams(location.hash.slice(1)).get('tree');
        if (raw && raw.length <= 20000) {
            const state = JSON.parse(raw);
            const index = graphs.findIndex(g => g.Project === state.manifest && g.Target === state.target && g.Ecosystem === state.ecosystem);
            if (index >= 0) {
                scope.value = String(index); load();
                if (state.report !== current().CheckId || current().IsSolution && state.projection !== 3) restoreNotice = text('viewChanged');
                else {
                    selected = typeof state.selected === 'string' && nodes.has(state.selected) ? state.selected : '';
                    expanded = new Set(Array.isArray(state.expanded) ? state.expanded.filter(i => Number.isInteger(i) && i >= 0 && i < current().Nodes.length).map(i => current().Nodes[i].Id) : []);
                    collapsed = new Set(Array.isArray(state.collapsed) ? state.collapsed.filter(i => Number.isInteger(i) && i >= 0 && i < current().Nodes.length).map(i => current().Nodes[i].Id) : []);
                }
                depth.value = Number.isFinite(state.depth) ? String(Math.min(20, Math.max(1, state.depth))) : current().IsSolution ? '1' : '3';
                search.value = typeof state.query === 'string' ? state.query.slice(0, 214) : '';
                risk.checked = state.risk === true;
            } else restoreNotice = text('viewChanged');
        }
    } catch { /* Invalid view links fall back to the current three-level graph. */ }
    schedule();
}
