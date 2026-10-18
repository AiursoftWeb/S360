using System.Text.Json;

namespace Aiursoft.S360.SDK;

/// <summary>
/// Builds human-readable introduction paths from the same restore/install graphs
/// whose package archives are checked by DependencyScanner.
/// </summary>
public static class DependencyIntroductionPaths
{
    public static string Identity(Dependency dependency) =>
        $"{dependency.Ecosystem}\n{(dependency.Ecosystem == "nuget" ? dependency.Name.ToLowerInvariant() : dependency.Name)}\n" +
        $"{dependency.Version}\n{TrustPattern.NormalizeSource(dependency.Source)}\n{dependency.Sha256.ToLowerInvariant()}";

    public static void AddNuGet(string assetsPath, IReadOnlyCollection<Dependency> dependencies,
        string project, Dictionary<string, List<string>> paths, List<DependencyGraphNode>? graph = null)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(assetsPath));
        var root = document.RootElement;
        var targets = root.GetProperty("targets");
        var byNameAndVersion = dependencies.Where(dependency => dependency.Ecosystem == "nuget")
            .ToLookup(dependency => NuGetKey(dependency.Name, dependency.Version), StringComparer.Ordinal);
        foreach (var target in targets.EnumerateObject())
        {
            var nodes = new Dictionary<string, (string Name, string Version, string Type, JsonElement Data)>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var item in target.Value.EnumerateObject())
            {
                var slash = item.Name.LastIndexOf('/');
                if (slash < 1 || !item.Value.TryGetProperty("type", out var type)) continue;
                if (type.GetString() is not ("package" or "project")) continue;
                if (!nodes.TryAdd(item.Name[..slash], (item.Name[..slash], item.Name[(slash + 1)..], type.GetString()!, item.Value)))
                    throw new InvalidOperationException($"NuGet target has ambiguous package names: {target.Name}");
            }
            var framework = target.Name.Split('/')[0];
            var direct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("project", out var metadata) &&
                metadata.TryGetProperty("frameworks", out var frameworks) &&
                frameworks.TryGetProperty(framework, out var frameworkData) &&
                frameworkData.TryGetProperty("dependencies", out var directDependencies))
                foreach (var dependency in directDependencies.EnumerateObject()) direct.Add(dependency.Name);

            if (graph != null)
            {
                var scopeNodes = new List<DependencyGraphNode>();
                DependencyGraphNode Node(string id, string kind, Dependency? package = null) => new()
                {
                    Project = project.Replace('\\', '/'), Ecosystem = "nuget", Target = target.Name,
                    Id = id, Kind = kind, Package = package
                };
                var rootNode = Node("$root", "root");
                rootNode.Children.AddRange(direct.Where(nodes.ContainsKey).Select(name => nodes[name].Name));
                if (root.TryGetProperty("project", out var projectData) &&
                    projectData.TryGetProperty("restore", out var restore) &&
                    restore.TryGetProperty("frameworks", out var restoreFrameworks) &&
                    restoreFrameworks.TryGetProperty(framework, out var restoreFramework) &&
                    restoreFramework.TryGetProperty("projectReferences", out var references) &&
                    root.TryGetProperty("libraries", out var libraries))
                {
                    var referencePaths = references.EnumerateObject().Select(r => Path.GetFullPath(r.Name)).ToHashSet();
                    var projectDirectory = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(assetsPath)))!;
                    foreach (var library in libraries.EnumerateObject())
                    {
                        if (!library.Value.TryGetProperty("msbuildProject", out var relative)) continue;
                        var absolute = Path.GetFullPath(relative.GetString()!, projectDirectory);
                        if (!referencePaths.Contains(absolute)) continue;
                        var name = library.Name[..library.Name.LastIndexOf('/')];
                        if (nodes.TryGetValue(name, out var referenceNode)) rootNode.Children.Add(referenceNode.Name);
                    }
                }
                rootNode.Children = rootNode.Children.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                scopeNodes.Add(rootNode);
                foreach (var (name, node) in nodes)
                {
                    var package = node.Type == "package" ? byNameAndVersion[NuGetKey(name, node.Version)].SingleOrDefault() : null;
                    if (node.Type == "package" && package == null)
                        throw new InvalidOperationException($"Restored graph package was not scanned: {name}@{node.Version}");
                    var item = Node(name, node.Type, package);
                    if (node.Data.TryGetProperty("dependencies", out var children))
                        item.Children.AddRange(children.EnumerateObject().Where(c => nodes.ContainsKey(c.Name))
                            .Select(c => nodes[c.Name].Name));
                    scopeNodes.Add(item);
                }
                graph.AddRange(scopeNodes);
            }
            var pending = new Queue<(string Name, string Path)>();
            foreach (var name in direct.Where(nodes.ContainsKey))
                pending.Enqueue((name, $"{project} → {Label(name, nodes[name].Version)}"));
            foreach (var name in nodes.Where(pair => pair.Value.Type == "project").Select(pair => pair.Key))
                pending.Enqueue((name, $"{project} → {name} (project reference)"));
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            while (pending.TryDequeue(out var current))
            {
                if (!visited.Add(current.Name)) continue;
                var node = nodes[current.Name];
                if (node.Type == "package")
                    foreach (var dependency in byNameAndVersion[NuGetKey(current.Name, node.Version)])
                        AddPath(paths, dependency, current.Path);
                if (!node.Data.TryGetProperty("dependencies", out var children)) continue;
                foreach (var child in children.EnumerateObject())
                    if (nodes.TryGetValue(child.Name, out var childNode))
                        pending.Enqueue((child.Name, current.Path + " → " + Label(child.Name, childNode.Version)));
            }
        }
        foreach (var dependency in dependencies.Where(dependency => dependency.Ecosystem == "nuget" &&
                     !paths.ContainsKey(Identity(dependency))))
            AddPath(paths, dependency, $"{project} → {Label(dependency.Name, dependency.Version)} " +
                "(restore graph root not identified)");
    }

    public static void AddNpm(string lockPath, IReadOnlyCollection<Dependency> dependencies,
        string project, Dictionary<string, List<string>> paths, List<DependencyGraphNode>? graph = null)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(lockPath));
        var projectDirectory = Path.GetDirectoryName(lockPath)!;
        var packages = document.RootElement.GetProperty("packages");
        var nodes = packages.EnumerateObject().ToDictionary(item => item.Name, item => item.Value,
            StringComparer.Ordinal);
        var byNameVersionAndSource = dependencies.Where(dependency => dependency.Ecosystem == "npm")
            .ToLookup(dependency => NpmKey(dependency.Name, dependency.Version, dependency.Source),
                StringComparer.Ordinal);
        if (!nodes.ContainsKey("")) throw new InvalidOperationException("npm lockfile has no root package.");
        var graphNodes = new Dictionary<string, DependencyGraphNode>(StringComparer.Ordinal);
        DependencyGraphNode GraphNode(string id, Dependency? package = null)
        {
            if (!graphNodes.TryGetValue(id, out var node))
                graphNodes.Add(id, node = new DependencyGraphNode
                {
                    Project = project.Replace('\\', '/'), Ecosystem = "npm", Id = id.Length == 0 ? "$root" : id,
                    Kind = id.Length == 0 ? "root" : "package", Package = package
                });
            return node;
        }
        GraphNode("");
        var pending = new Queue<(string LockPath, string Path)>();
        pending.Enqueue(("", project));
        var visited = new HashSet<string>(StringComparer.Ordinal);
        while (pending.TryDequeue(out var current))
        {
            if (!visited.Add(current.LockPath)) continue;
            var node = nodes[current.LockPath];
            foreach (var group in current.LockPath == ""
                         ? new[] { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" }
                         : ["dependencies", "optionalDependencies", "peerDependencies"])
            {
                if (!node.TryGetProperty(group, out var children) || children.ValueKind != JsonValueKind.Object) continue;
                foreach (var child in children.EnumerateObject())
                {
                    var childPath = ResolveNpmPath(current.LockPath, child.Name, nodes);
                    if (childPath == null || !nodes[childPath].TryGetProperty("version", out var versionElement)) continue;
                    if (!Directory.Exists(Path.Combine(projectDirectory,
                            childPath.Replace('/', Path.DirectorySeparatorChar)))) continue;
                    var childNode = nodes[childPath];
                    var version = versionElement.GetString();
                    var resolved = childNode.TryGetProperty("resolved", out var resolvedElement) &&
                                   Uri.TryCreate(resolvedElement.GetString(), UriKind.Absolute, out var uri)
                        ? TrustPattern.NormalizeSource(uri.GetLeftPart(UriPartial.Authority)) : null;
                    var name = childNode.TryGetProperty("name", out var declaredName) &&
                               declaredName.ValueKind == JsonValueKind.String
                        ? declaredName.GetString()! : childPath[(childPath.LastIndexOf("node_modules/", StringComparison.Ordinal) + 13)..];
                    var childLabel = child.Name == name ? Label(name, version ?? "?") :
                        $"{child.Name} (alias for {Label(name, version ?? "?")})";
                    var introduction = current.Path + " → " + childLabel;
                    foreach (var dependency in byNameVersionAndSource[NpmKey(name, version, resolved)])
                    {
                        AddPath(paths, dependency, introduction);
                        GraphNode(childPath, dependency);
                        var parent = GraphNode(current.LockPath);
                        if (!parent.Children.Contains(childPath, StringComparer.Ordinal)) parent.Children.Add(childPath);
                    }
                    pending.Enqueue((childPath, introduction));
                }
            }
        }
        graph?.AddRange(graphNodes.Values);
    }

    private static string? ResolveNpmPath(string parentPath, string name,
        IReadOnlyDictionary<string, JsonElement> nodes)
    {
        var prefix = parentPath;
        while (true)
        {
            var candidate = prefix.Length == 0 ? $"node_modules/{name}" : $"{prefix}/node_modules/{name}";
            if (nodes.ContainsKey(candidate)) return candidate;
            var separator = prefix.LastIndexOf("/node_modules/", StringComparison.Ordinal);
            if (separator < 0)
            {
                if (prefix.Length == 0) return null;
                prefix = "";
            }
            else prefix = prefix[..separator];
        }
    }

    private static string Label(string name, string version) => $"{name}@{version}";

    private static string NuGetKey(string name, string version) => $"{name.ToLowerInvariant()}\n{version}";

    private static string NpmKey(string name, string? version, string? source) =>
        $"{name}\n{version}\n{source}";

    private static void AddPath(Dictionary<string, List<string>> paths, Dependency dependency, string path)
    {
        var key = Identity(dependency);
        if (!paths.TryGetValue(key, out var known)) paths.Add(key, known = []);
        if (known.Count < 3 && !known.Contains(path, StringComparer.Ordinal)) known.Add(path);
    }
}
