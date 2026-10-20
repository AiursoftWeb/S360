using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace Aiursoft.S360.SDK;

/// <summary>
/// One solution, including every evaluated project and its resolved dependencies.
/// Nodes have global identities. Edges retain the restore context that proves them:
/// paths must never join edges from different contexts just because a node is shared.
/// </summary>
public class SolutionDependencyGraph
{
    public int SchemaVersion { get; set; } = 1;
    public string SolutionPath { get; set; } = string.Empty;
    public List<SolutionGraphNode> Nodes { get; set; } = [];
    public List<SolutionRestoreContext> Contexts { get; set; } = [];

    public string? ValidatePart()
    {
        if (SchemaVersion != 1 || !IsPortablePath(SolutionPath) || SolutionPath.Length > 512 || SolutionPath.StartsWith("../", StringComparison.Ordinal) ||
            !SolutionPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || Nodes == null || Contexts == null ||
            Nodes.Count > 5000 || Contexts.Count > 5000)
            return "Invalid solution graph batch.";
        if (Nodes.Any(n => n == null || string.IsNullOrWhiteSpace(n.Id) || n.Id.Length > 1100 ||
                (n.ProjectPath == null) == (n.Package == null) ||
                n.ProjectPath != null && !IsPortablePath(n.ProjectPath) ||
                n.Package != null && !Validator.TryValidateObject(n.Package, new ValidationContext(n.Package), [], true)))
            return "Invalid solution graph node.";
        foreach (var context in Contexts)
        {
            if (context == null || !IsPortablePath(context.ProjectPath) || string.IsNullOrWhiteSpace(context.Target) ||
                context.Target.Length > 200 || context.Edges == null || context.ProjectTargets == null ||
                context.Edges.Count > 5000 || context.ProjectTargets.Count > 10000 ||
                context.ProjectTargets.Any(p => !IsPortablePath(p.Key) || string.IsNullOrWhiteSpace(p.Value) || p.Value.Length > 200) ||
                context.Edges.Any(e => e == null || string.IsNullOrWhiteSpace(e.ParentId) || e.ParentId.Length > 1100 ||
                    string.IsNullOrWhiteSpace(e.ChildId) || e.ChildId.Length > 1100))
                return "Invalid solution restore context.";
        }
        return null;
    }

    public static SolutionDependencyGraph Assemble(IReadOnlyCollection<SolutionDependencyGraph> parts)
    {
        if (parts.Count == 0) throw new ArgumentException("No solution graph was reported.");
        var graph = new SolutionDependencyGraph { SolutionPath = parts.First().SolutionPath };
        var contexts = new Dictionary<(string Project, string Target), SolutionRestoreContext>();
        foreach (var part in parts)
        {
            var error = part.ValidatePart();
            if (error != null) throw new ArgumentException(error);
            if (part.SolutionPath != graph.SolutionPath)
                throw new ArgumentException("All graph batches must describe the same solution.");
            graph.Nodes.AddRange(part.Nodes);
            foreach (var fragment in part.Contexts)
            {
                var key = (fragment.ProjectPath, fragment.Target);
                if (!contexts.TryGetValue(key, out var context))
                {
                    context = new SolutionRestoreContext { ProjectPath = fragment.ProjectPath, Target = fragment.Target };
                    contexts.Add(key, context);
                }
                foreach (var pair in fragment.ProjectTargets)
                {
                    if (context.ProjectTargets.TryGetValue(pair.Key, out var target) && target != pair.Value)
                        throw new ArgumentException("Batches disagree about a referenced project's framework.");
                    context.ProjectTargets[pair.Key] = pair.Value;
                }
                context.Edges.AddRange(fragment.Edges);
            }
        }
        graph.Contexts = contexts.Values.ToList();
        return graph;
    }

    public static string ProjectId(string path) => "project:" + path;

    public static string PackageId(Dependency package) => "package:" + Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(DependencyIntroductionPaths.Identity(package))));

    /// <summary>Paths are portable and relative to the solution directory, including external references.</summary>
    public static bool IsPortablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1024 || path.StartsWith('/') ||
            path.Contains('\\') || path.Contains(':') || path.Any(char.IsControl)) return false;
        var parts = path.Split('/');
        return !parts.Any(part => part is "" or ".") &&
            !parts.SkipWhile(part => part == "..").Contains("..");
    }

    /// <summary>Validate the assembled report, never a partial transport batch.</summary>
    public string? Validate(IReadOnlyCollection<Dependency> dependencies, int projectCount)
    {
        if (SchemaVersion != 1 || !IsPortablePath(SolutionPath) || SolutionPath.Length > 512 || SolutionPath.StartsWith("../", StringComparison.Ordinal) ||
            !SolutionPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) || Nodes == null || Contexts == null)
            return "Invalid solution graph header.";

        var nodes = new Dictionary<string, SolutionGraphNode>(StringComparer.Ordinal);
        var projects = new HashSet<string>(StringComparer.Ordinal);
        var artifacts = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in Nodes)
        {
            if (node == null || string.IsNullOrWhiteSpace(node.Id) || !nodes.TryAdd(node.Id, node) ||
                (node.ProjectPath == null) == (node.Package == null))
                return "Solution nodes must have unique IDs and represent either a project or a package.";
            if (node.ProjectPath != null)
            {
                if (!IsPortablePath(node.ProjectPath) ||
                    Path.GetExtension(node.ProjectPath).ToLowerInvariant() is not (".csproj" or ".fsproj" or ".vbproj") ||
                    node.Id != ProjectId(node.ProjectPath) ||
                    !projects.Add(node.ProjectPath)) return "Invalid solution project identity.";
            }
            else
            {
                var package = node.Package!;
                if (node.IsSolutionMember || package.Ecosystem != "nuget" ||
                    !Validator.TryValidateObject(package, new ValidationContext(package), [], true) ||
                    !TrustPattern.IsValidConcretePackage(package.Ecosystem, package.Name, package.Version))
                    return "Invalid solution package.";
                try
                {
                    if (node.Id != PackageId(package)) return "Package identity does not match its archive.";
                    artifacts.Add(DependencyIntroductionPaths.Identity(package));
                }
                catch (ArgumentException) { return "Invalid solution package source."; }
            }
        }
        if (projects.Count == 0 || projects.Count != projectCount || !Nodes.Any(n => n.IsSolutionMember))
            return "The solution must describe every scanned project and its solution membership.";
        try
        {
            if (!artifacts.SetEquals(dependencies.Where(d => d.Ecosystem == "nuget")
                    .Select(DependencyIntroductionPaths.Identity)))
                return "Solution packages must exactly match the checked NuGet artifacts.";
        }
        catch (ArgumentException) { return "Invalid checked package source."; }

        var contexts = new HashSet<(string Project, string Target)>();
        var evaluatedProjects = new HashSet<string>(StringComparer.Ordinal);
        var usedPackages = new HashSet<string>(StringComparer.Ordinal);
        foreach (var context in Contexts)
        {
            if (context == null || !projects.Contains(context.ProjectPath) ||
                string.IsNullOrWhiteSpace(context.Target) || context.Target.Length > 200 ||
                !contexts.Add((context.ProjectPath, context.Target)) || context.Edges == null || context.ProjectTargets == null)
                return "Each restore context must identify a unique project and target.";
            if (context.ProjectTargets.Any(pair => !projects.Contains(pair.Key) ||
                    string.IsNullOrWhiteSpace(pair.Value) || pair.Value.Length > 200))
                return "Referenced framework metadata must identify a solution project and framework.";
            evaluatedProjects.Add(context.ProjectPath);
            var edges = new HashSet<(string Parent, string Child)>();
            foreach (var edge in context.Edges)
            {
                if (edge == null || edge.ParentId == null || edge.ChildId == null ||
                    !nodes.ContainsKey(edge.ParentId) || !nodes.ContainsKey(edge.ChildId) ||
                    !edges.Add((edge.ParentId, edge.ChildId)))
                    return "Solution edges must be unique within their context and reference existing nodes.";
                if (nodes[edge.ParentId].Package != null && nodes[edge.ChildId].ProjectPath != null)
                    return "A package cannot reference a solution project.";
            }
            var reached = Reachable(context, ProjectId(context.ProjectPath));
            if (context.Edges.Any(e => !reached.Contains(e.ParentId)))
                return "Every dependency edge must have a path from its context's project.";
            if (context.ProjectTargets.Keys.Any(path => !reached.Contains(ProjectId(path))))
                return "Referenced frameworks must belong to a project used in their restore context.";
            usedPackages.UnionWith(reached.Where(id => nodes[id].Package != null));
        }
        if (!evaluatedProjects.SetEquals(projects)) return "Every solution project needs an evaluated restore context.";
        if (!usedPackages.SetEquals(Nodes.Where(n => n.Package != null).Select(n => n.Id)))
            return "Every package needs a real introduction path in the solution.";
        var projectReferences = Contexts.SelectMany(c => c.Edges)
            .Where(e => nodes[e.ParentId].ProjectPath != null && nodes[e.ChildId].ProjectPath != null)
            .ToLookup(e => e.ParentId, e => e.ChildId, StringComparer.Ordinal);
        var connected = new HashSet<string>(StringComparer.Ordinal);
        var pendingProjects = new Stack<string>(Nodes.Where(n => n.IsSolutionMember).Select(n => n.Id));
        while (pendingProjects.TryPop(out var id))
        {
            if (!connected.Add(id)) continue;
            foreach (var child in projectReferences[id]) pendingProjects.Push(child);
        }
        if (connected.Count != projects.Count)
            return "Referenced projects must be reachable from an actual solution member.";
        return null;
    }

    public static HashSet<string> Reachable(SolutionRestoreContext context, string root)
    {
        var children = context.Edges.ToLookup(e => e.ParentId, e => e.ChildId, StringComparer.Ordinal);
        var result = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var id))
        {
            if (!result.Add(id)) continue;
            foreach (var child in children[id]) pending.Push(child);
        }
        return result;
    }

    /// <summary>Find introduction paths throughout the solution without crossing restore contexts.</summary>
    public List<SolutionRestoreContext> PathsTo(IReadOnlySet<string> packageIds)
    {
        var result = new List<SolutionRestoreContext>();
        foreach (var context in Contexts)
        {
            var reachable = Reachable(context, ProjectId(context.ProjectPath));
            var parents = context.Edges.ToLookup(e => e.ChildId, e => e.ParentId, StringComparer.Ordinal);
            var included = new HashSet<string>(StringComparer.Ordinal);
            var pending = new Stack<string>(packageIds.Where(reachable.Contains));
            while (pending.TryPop(out var id))
            {
                if (!included.Add(id)) continue;
                foreach (var parent in parents[id]) pending.Push(parent);
            }
            if (!included.Contains(ProjectId(context.ProjectPath))) continue;
            result.Add(new SolutionRestoreContext
            {
                ProjectPath = context.ProjectPath, Target = context.Target,
                ProjectTargets = context.ProjectTargets.Where(pair => included.Contains(ProjectId(pair.Key)))
                    .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal),
                Edges = context.Edges.Where(e => included.Contains(e.ParentId) && included.Contains(e.ChildId)).ToList()
            });
        }
        return result;
    }
}

public class SolutionGraphNode
{
    public string Id { get; set; } = string.Empty;
    public string? ProjectPath { get; set; }
    public bool IsSolutionMember { get; set; }
    public Dependency? Package { get; set; }
}

/// <summary>Resolved edges from one project's assets target (framework and optional runtime identifier).</summary>
public class SolutionRestoreContext
{
    public string ProjectPath { get; set; } = string.Empty;
    public string Target { get; set; } = string.Empty;
    public Dictionary<string, string> ProjectTargets { get; set; } = new(StringComparer.Ordinal);
    public List<SolutionDependencyEdge> Edges { get; set; } = [];
}

public class SolutionDependencyEdge
{
    public string ParentId { get; set; } = string.Empty;
    public string ChildId { get; set; } = string.Empty;
}
