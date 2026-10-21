// Project identity is global. Resolved paths stay inside the context that produced them.
// Dotted project-reference edges describe structure only; they are never traversed as package paths.
export function solutionView(solution) {
    const graph = solution.Graph;
    const definitions = new Map(graph.Nodes.map(node => [node.Id, node]));
    const states = new Map(solution.Packages.map(node => [node.Id, node]));
    const projects = graph.Nodes.filter(node => node.ProjectPath).sort((a, b) => a.ProjectPath.localeCompare(b.ProjectPath));
    const empty = { Status: 0, Reason: null, Advisories: [], Projects: [], Purposes: [], Children: [] };
    const root = { ...empty, Id: '$solution', Kind: 'root', Label: graph.SolutionPath,
        Children: projects.map(node => node.Id) };
    const nodes = [root];
    const projectNodes = new Map(projects.map(node => {
        const view = { ...empty, Id: node.Id, Kind: 'project', Label: node.ProjectPath.split("/").at(-1),
            ProjectPath: node.ProjectPath, IsSolutionMember: node.IsSolutionMember, Children: [], Targets: [], RiskCount: 0 };
        nodes.push(view);
        return [node.Id, view];
    }));
    const references = new Map(), packageUsers = new Map();
    graph.Contexts.forEach((context, index) => {
        const ownerId = `project:${context.ProjectPath}`, prefix = `context:${index}:`;
        const idFor = id => id === ownerId ? ownerId : prefix + id;
        const owner = projectNodes.get(ownerId);
        const direct = new Set(context.Edges.filter(edge => edge.ParentId === ownerId).map(edge => edge.ChildId));
        const outgoing = new Map(), ids = new Set([ownerId]);
        for (const edge of context.Edges) {
            if (!outgoing.has(edge.ParentId)) outgoing.set(edge.ParentId, []);
            outgoing.get(edge.ParentId).push(idFor(edge.ChildId));
            ids.add(edge.ParentId); ids.add(edge.ChildId);
            if (definitions.get(edge.ParentId)?.ProjectPath && definitions.get(edge.ChildId)?.ProjectPath) {
                const key = JSON.stringify([edge.ParentId, edge.ChildId]);
                references.set(key, [edge.ParentId, edge.ChildId]);
            }
        }
        if (!owner.Targets.includes(context.Target)) owner.Targets.push(context.Target);
        owner.Children.push(...(outgoing.get(ownerId) || []));
        for (const id of ids) {
            if (id === ownerId) continue;
            const definition = definitions.get(id), state = states.get(id);
            const view = {
                ...empty, ...state, Id: idFor(id), CanonicalId: id,
                ArtifactId: definition.Package ? id : null,
                IsDirect: definition.Package ? direct.has(id) : null,
                Package: definition.Package,
                Kind: definition.ProjectPath ? 'project-reference' : 'package',
                Label: definition.ProjectPath?.split("/").at(-1),
                ProjectPath: definition.ProjectPath,
                RootProjectPath: context.ProjectPath, Target: context.Target,
                ReferencedTarget: context.ProjectTargets[definition.ProjectPath] || null,
                Children: outgoing.get(id) || [], RiskCount: 0
            };
            nodes.push(view);
            if (definition.Package) {
                if (!packageUsers.has(id)) packageUsers.set(id, new Set());
                packageUsers.get(id).add(ownerId);
            }
        }
    });
    // Framework is an attribute of the owning project, never an extra dependency.
    // Package occurrences remain context-scoped; label multi-target paths explicitly.
    for (const node of nodes) {
        if (node.Targets) node.Targets.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
        if (node.RootProjectPath) {
            const owner = projectNodes.get(`project:${node.RootProjectPath}`);
            node.ShowTarget = owner.Targets.length > 1;
        }
    }
    // Compute folded risk markers without merging traversal across restore contexts.
    const byId = new Map(nodes.map(node => [node.Id, node]));
    const parents = new Map(nodes.map(node => [node.Id, []]));
    for (const node of nodes) for (const child of node.Children) parents.get(child).push(node.Id);
    for (const node of nodes.filter(item => item.ArtifactId && item.Advisories.length)) {
        const visited = new Set(), pending = [...parents.get(node.Id)];
        while (pending.length) {
            const id = pending.pop();
            if (visited.has(id)) continue;
            visited.add(id);
            const parent = byId.get(id);
            parent.RiskArtifacts ??= new Set();
            parent.RiskArtifacts.add(node.ArtifactId);
            pending.push(...parents.get(id));
        }
    }
    for (const node of nodes) {
        node.RiskCount = node.RiskArtifacts?.size || 0;
        delete node.RiskArtifacts;
        node.UsedBy = node.ArtifactId ? [...(packageUsers.get(node.ArtifactId) || [])].sort() : [];
    }
    return {
        Project: graph.SolutionPath, Ecosystem: 'nuget', Target: '', CheckId: solution.CheckId,
        Nodes: nodes, ReferenceEdges: [...references.values()], IsSolution: true
    };
}
