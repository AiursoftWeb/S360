// Match the local Mermaid distribution used by OllamaGateway; no remote renderer.
const host = document.querySelector('.s360-graph');
if (host) {
    const text = key => host.querySelector(`[data-key="${key}"]`).textContent;
    const graphs = JSON.parse(host.querySelector('.s360-graph-data').textContent);
    const scope = host.querySelector('.s360-graph-scope');
    const search = host.querySelector('.s360-graph-search');
    const focus = host.querySelector('.s360-graph-focus');
    const canvas = host.querySelector('.s360-graph-canvas');
    const notice = host.querySelector('.s360-graph-notice');
    const detail = host.querySelector('.s360-graph-detail');
    const compact = window.matchMedia('(max-width: 767px)');
    let sequence = 0;
    let mermaid;
    let pending;
    const state = node => text(['compliant', 'pending', 'problem'][node.Status]);
    const name = node => node.Package ? `${node.Package.Name}@${node.Package.Version}` : node.Id;
    // Numeric entities keep untrusted package/path text out of Mermaid's grammar and HTML.
    const escapeLabel = value => Array.from(value).map(c => /[a-zA-Z0-9 ._/@-]/.test(c) ? c : `#${c.codePointAt(0)};`).join('');
    const current = () => graphs[Number(scope.value)];
    function populate(preferIssue = false) {
        const selected = focus.value;
        const query = search.value.toLowerCase();
        focus.replaceChildren(new Option(text('all'), ''));
        for (const node of current().Nodes.filter(n => n.Package &&
            `${name(n)} ${n.Id}`.toLowerCase().includes(query))) {
            const option = new Option(`${name(node)} · ${state(node)} · ${node.Id}`, node.Id);
            focus.add(option);
        }
        if (Array.from(focus.options).some(o => o.value === selected)) focus.value = selected;
        if (preferIssue) {
            const issue = current().Nodes.find(n => n.Advisories.length) || current().Nodes.find(n => n.Package && n.Status === 2);
            if (issue) focus.value = issue.Id;
        }
        if (query && !focus.value && focus.options.length > 1) focus.selectedIndex = 1;
        if (query && focus.options.length === 1) {
            ++sequence;
            canvas.replaceChildren();
            detail.textContent = '';
            notice.textContent = text('empty');
        } else schedule();
    }
    function schedule() {
        const ticket = ++sequence;
        clearTimeout(pending);
        pending = setTimeout(() => render(ticket), 120);
    }
    async function render(ticket) {
        const graph = current();
        const nodes = new Map(graph.Nodes.map(n => [n.Id, n]));
        const parents = new Map(graph.Nodes.map(n => [n.Id, []]));
        for (const node of graph.Nodes) for (const child of node.Children) parents.get(child)?.push(node.Id);
        const selected = nodes.get(focus.value);
        const visible = new Set();
        let limited = false;
        function visit(starts, adjacent) {
            const seen = new Set();
            const queue = [...starts];
            for (let i = 0; i < queue.length; i++) {
                const id = queue[i];
                if (seen.has(id) || !nodes.has(id)) continue;
                seen.add(id);
                if (!visible.has(id) && visible.size >= 150) { limited = true; break; }
                visible.add(id);
                queue.push(...adjacent(id));
            }
        }
        if (selected) {
            visit([selected.Id], id => parents.get(id));
            visit([selected.Id], id => nodes.get(id).Children);
        } else {
            visit(graph.Nodes.filter(n => n.Kind === 'root').map(n => n.Id), id => nodes.get(id).Children);
            // Show disconnected restore nodes too, without inventing root edges.
            visit(graph.Nodes.map(n => n.Id), id => nodes.get(id).Children);
        }
        const ids = new Map([...visible].map((id, i) => [id, `n${i}`]));
        const code = [compact.matches ? 'flowchart TD' : 'flowchart LR',
            'classDef good fill:#e6f5ec,stroke:#25834b,color:#164d2c',
            'classDef bad fill:#fce8ea,stroke:#bd2c40,color:#781c2a',
            'classDef pending fill:#edf0f4,stroke:#748092,color:#354052',
            'classDef project fill:#e8f0ff,stroke:#496fad,color:#243d66'];
        for (const id of visible) {
            const node = nodes.get(id);
            const lines = node.Kind === 'root' ? [graph.Project] : node.Kind === 'project' ? [node.Id, text('reference')] :
                [name(node), state(node), ...node.Advisories.slice(0, 3)];
            const label = lines.flatMap(line => {
                const shortened = line.length > 120 ? line.slice(0, 117) + '...' : line;
                return shortened.match(compact.matches ? /.{1,18}/gu : /.{1,40}/gu) || [''];
            }).map(escapeLabel).join('<br/>');
            code.push(`${ids.get(id)}["${label}"]:::${node.Package ? ['good', 'pending', 'bad'][node.Status] : 'project'}`);
        }
        let edges = 0;
        for (const id of visible) for (const child of nodes.get(id).Children) {
            if (!visible.has(child)) continue;
            if (++edges > 400) { limited = true; continue; }
            code.push(`${ids.get(id)} --> ${ids.get(child)}`);
        }
        notice.textContent = limited ? text('limited') : '';
        detail.textContent = selected ? `${name(selected)} · ${state(selected)} · ${selected.Reason || ''} · ${selected.Package.Source} · ${selected.Id}` : '';
        try {
            mermaid ??= (await import('/node_modules/mermaid/dist/mermaid.esm.mjs')).default;
            mermaid.initialize({ startOnLoad: false, securityLevel: 'strict', theme: 'default', maxTextSize: 250000,
                flowchart: { htmlLabels: false, useMaxWidth: false } });
            const result = await mermaid.render(`s360_dependency_${ticket}`, code.join('\n'));
            if (ticket === sequence) canvas.innerHTML = result.svg;
        } catch {
            if (ticket === sequence) {
                canvas.replaceChildren();
                notice.textContent = text('failed');
            }
        }
    }
    scope.addEventListener('change', () => { search.value = ''; focus.value = ''; populate(true); });
    search.addEventListener('input', () => populate());
    focus.addEventListener('change', schedule);
    compact.addEventListener('change', schedule);
    populate(true);
}
