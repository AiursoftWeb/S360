// The solution is the page scope, not a dependency. Only projects and packages are drawn.
export function solutionView(solution) {
    const graph = solution.Graph;
    const definitions = new Map(graph.Nodes.map(node => [node.Id, node]));
    const states = new Map(solution.Packages.map(node => [node.Id, node]));
    const empty = { Status: 0, Reason: null, Advisories: [], Projects: [], Purposes: [] };
    const nodes = new Map(), signatures = new Map(), contexts = [];
    const projects = graph.Nodes.filter(node => node.ProjectPath).sort((a, b) => a.ProjectPath.localeCompare(b.ProjectPath));
    for (const project of projects) nodes.set(project.Id, {
        ...empty, ...project, Kind: 'project', Label: project.ProjectPath.split('/').at(-1).replace(/\.csproj$/i, ''),
        Children: [], Targets: [], Resolutions: [], RiskArtifacts: new Set()
    });
    graph.Contexts.forEach((context, index) => {
        const outgoing = new Map(), parents = new Map(), ids = new Set();
        for (const edge of context.Edges) {
            if (!outgoing.has(edge.ParentId)) outgoing.set(edge.ParentId, []);
            if (!parents.has(edge.ChildId)) parents.set(edge.ChildId, []);
            outgoing.get(edge.ParentId).push(edge.ChildId);
            parents.get(edge.ChildId).push(edge.ParentId);
            ids.add(edge.ParentId); ids.add(edge.ChildId);
        }
        const resolved = new Map(), visiting = new Set();
        // Share a package card only when its complete resolved subtree is identical.
        // Equal name/version alone is insufficient across frameworks or version conflicts.
        function identity(id) {
            if (resolved.has(id)) return resolved.get(id);
            if (visiting.has(id)) return `cycle:${index}:${id}`;
            visiting.add(id);
            const children = (outgoing.get(id) || []).map(identity).sort();
            const key = JSON.stringify([id, children]);
            if (!signatures.has(key)) signatures.set(key, `resolved:${signatures.size}`);
            const value = signatures.get(key);
            resolved.set(id, value); visiting.delete(id);
            return value;
        }
        const viewId = id => definitions.get(id).ProjectPath ? id : identity(id);
        const ownerId = `project:${context.ProjectPath}`;
        const owner = nodes.get(ownerId);
        if (!owner.Targets.includes(context.Target)) owner.Targets.push(context.Target);
        const direct = new Set(outgoing.get(ownerId) || []);
        for (const id of ids) {
            const definition = definitions.get(id), state = states.get(id), key = viewId(id);
            if (!nodes.has(key)) nodes.set(key, {
                ...empty, ...state, Id: key, ArtifactId: id, Package: definition.Package,
                Kind: 'package', IsDirect: false, Children: [], Resolutions: [], UsedBy: [], RiskArtifacts: new Set()
            });
            const node = nodes.get(key);
            const target = id === ownerId ? context.Target : context.ProjectTargets[definition.ProjectPath];
            if (node.Kind === 'project' && target && !node.Targets.includes(target)) node.Targets.push(target);
            node.Resolutions.push({ ProjectPath: context.ProjectPath, Target: context.Target });
            for (const child of outgoing.get(id) || []) {
                if (!node.Children.includes(viewId(child))) node.Children.push(viewId(child));
            }
            if (node.Package) {
                node.IsDirect ||= direct.has(id);
                if (!node.UsedBy.includes(ownerId)) node.UsedBy.push(ownerId);
            }
        }
        // Compute risks in each original restore context before sharing any display nodes.
        for (const id of ids) {
            if (!states.get(id)?.Advisories.length) continue;
            const visited = new Set(), pending = [...(parents.get(id) || [])];
            while (pending.length) {
                const parent = pending.pop();
                if (visited.has(parent)) continue;
                visited.add(parent); nodes.get(viewId(parent)).RiskArtifacts.add(id);
                pending.push(...(parents.get(parent) || []));
            }
        }
        contexts.push(context.Edges.map(edge => [viewId(edge.ParentId), viewId(edge.ChildId)]));
    });
    for (const node of nodes.values()) {
        node.RiskCount = node.RiskArtifacts.size; delete node.RiskArtifacts;
        node.Targets?.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
        node.Resolutions = [...new Map(node.Resolutions.map(item => [JSON.stringify(item), item])).values()];
    }
    return {
        Project: graph.SolutionPath, Ecosystem: 'nuget', Target: '', CheckId: solution.CheckId,
        Nodes: [...nodes.values()], RootIds: projects.map(node => node.Id), Contexts: contexts, IsSolution: true
    };
}

// Search and vulnerability paths follow one reported restore context at a time.
// Traversing the union of all project edges would invent cross-framework paths.
export function solutionPaths(graph, seeds) {
    const visible = new Set(), edges = new Map();
    for (const context of graph.Contexts) {
        const parents = new Map(), present = new Set(context.flat());
        for (const [from, to] of context) {
            if (!parents.has(to)) parents.set(to, []);
            parents.get(to).push(from);
        }
        const included = new Set(), pending = [...seeds].filter(id => present.has(id));
        while (pending.length) {
            const id = pending.pop();
            if (included.has(id)) continue;
            included.add(id); visible.add(id);
            for (const parent of parents.get(id) || []) {
                edges.set(JSON.stringify([parent, id]), [parent, id]); pending.push(parent);
            }
        }
    }
    for (const id of seeds) visible.add(id);
    return { visible, edges: [...edges.values()] };
}
