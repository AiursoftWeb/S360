using System.Text.Json;

namespace Aiursoft.S360.SDK;

/// <summary>Collects identities and resolved edges from the same assets used for archive verification.</summary>
public static class SolutionGraphCollector
{
    public static void AddProject(SolutionDependencyGraph graph, string assetsPath,
        IReadOnlyCollection<Dependency> dependencies, string solutionDirectory)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(assetsPath));
        var root = document.RootElement;
        var project = root.GetProperty("project");
        var restore = project.GetProperty("restore");
        var projectFile = Path.GetFullPath(restore.GetProperty("projectPath").GetString()!);
        var projectDirectory = Path.GetDirectoryName(projectFile)!;
        string Relative(string path) => Path.GetRelativePath(solutionDirectory, path).Replace('\\', '/');
        var projectPath = Relative(projectFile);
        var projectId = SolutionDependencyGraph.ProjectId(projectPath);
        var known = graph.Nodes.ToDictionary(n => n.Id, StringComparer.Ordinal);
        if (!known.ContainsKey(projectId)) throw new InvalidOperationException($"Project is outside the evaluated solution: {projectPath}");
        var packages = dependencies.Where(d => d.Ecosystem == "nuget")
            .ToLookup(d => $"{d.Name}/{d.Version}", StringComparer.OrdinalIgnoreCase);
        var libraries = root.GetProperty("libraries");
        foreach (var target in root.GetProperty("targets").EnumerateObject())
        {
            var context = new SolutionRestoreContext { ProjectPath = projectPath, Target = target.Name };
            var resolved = new Dictionary<string, (string Id, JsonElement Data)>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in target.Value.EnumerateObject())
            {
                var type = item.Value.GetProperty("type").GetString();
                if (type is not ("package" or "project")) continue;
                var name = item.Name[..item.Name.LastIndexOf('/')];
                string id;
                if (type == "project")
                {
                    // The restore project name is not a file identity (PackageId may override it).
                    var relative = libraries.GetProperty(item.Name).GetProperty("msbuildProject").GetString()!;
                    id = SolutionDependencyGraph.ProjectId(Relative(Path.GetFullPath(relative, projectDirectory)));
                    if (!known.ContainsKey(id))
                        throw new InvalidOperationException($"Referenced project is outside the evaluated solution: {relative}");
                    if (item.Value.TryGetProperty("framework", out var selectedFramework) &&
                        selectedFramework.ValueKind == JsonValueKind.String)
                        context.ProjectTargets.Add(known[id].ProjectPath!, selectedFramework.GetString()!);
                }
                else
                {
                    var package = packages[item.Name].SingleOrDefault() ??
                        throw new InvalidOperationException($"Restored graph package was not scanned: {item.Name}");
                    id = SolutionDependencyGraph.PackageId(package);
                    if (!known.ContainsKey(id))
                    {
                        var node = new SolutionGraphNode { Id = id, Package = package };
                        known.Add(id, node);
                        graph.Nodes.Add(node);
                    }
                }
                if (!resolved.TryAdd(name, (id, item.Value)))
                    throw new InvalidOperationException($"Ambiguous NuGet identity in {projectPath}: {name}");
            }
            var edges = new HashSet<(string Parent, string Child)>();
            void Edge(string parent, string child)
            {
                if (edges.Add((parent, child)))
                    context.Edges.Add(new SolutionDependencyEdge { ParentId = parent, ChildId = child });
            }
            var framework = target.Name.Split('/')[0];
            if (project.TryGetProperty("frameworks", out var frameworks) &&
                frameworks.TryGetProperty(framework, out var frameworkData) &&
                frameworkData.TryGetProperty("dependencies", out var direct))
                foreach (var dependency in direct.EnumerateObject())
                    if (resolved.TryGetValue(dependency.Name, out var child)) Edge(projectId, child.Id);
            if (restore.TryGetProperty("frameworks", out var restoreFrameworks) &&
                restoreFrameworks.TryGetProperty(framework, out var restoreFramework) &&
                restoreFramework.TryGetProperty("projectReferences", out var references))
                foreach (var reference in references.EnumerateObject())
                {
                    var id = SolutionDependencyGraph.ProjectId(Relative(Path.GetFullPath(reference.Name, projectDirectory)));
                    if (!known.ContainsKey(id))
                        throw new InvalidOperationException($"Referenced project is outside the evaluated solution: {reference.Name}");
                    Edge(projectId, id);
                }
            foreach (var node in resolved.Values)
                if (node.Data.TryGetProperty("dependencies", out var children))
                    foreach (var child in children.EnumerateObject())
                        if (resolved.TryGetValue(child.Name, out var dependency)) Edge(node.Id, dependency.Id);
            graph.Contexts.Add(context);
        }
    }
}
