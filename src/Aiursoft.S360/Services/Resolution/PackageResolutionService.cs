using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public record DirectPackage(string Name, string Version);
public record ResolutionEdge(Dependency? Parent, Dependency Child);
public record ResolutionReport(List<Dependency> Dependencies, List<ResolutionEdge> Edges,
    List<string> SkippedOptional, string Context);

/// <summary>Prepares a rule request from names and versions. Dependency discovery belongs to build clients.</summary>
public class PackageResolutionService
{
    public Task<ResolutionReport> ResolveAsync(string ecosystem, string source, IReadOnlyList<DirectPackage> direct)
    {
        source = TrustPattern.NormalizeSource(source);
        if (direct.Count is < 1 or > 20 || direct.Any(p => !TrustPattern.IsValidConcretePackage(ecosystem, p.Name, p.Version)))
            throw new ArgumentException("Enter exact package names and versions.");
        var dependencies = direct.Select(p => new Dependency
            { Ecosystem = ecosystem, Name = p.Name, Version = p.Version, Source = source }).ToList();
        return Task.FromResult(new ResolutionReport(dependencies,
            dependencies.Select(d => new ResolutionEdge(null, d)).ToList(), [], "Requested packages; transitive dependencies are reported by CI."));
    }

    public static void ValidateGraph(IReadOnlyCollection<Dependency> dependencies,
        IReadOnlyCollection<ResolutionEdge> edges)
    {
        if (dependencies.Count == 0 || edges.Count == 0)
            throw new InvalidOperationException("The dependency resolution graph is empty.");
        var known = dependencies.Select(DependencyKey).ToHashSet(StringComparer.Ordinal);
        if (known.Count != dependencies.Count)
            throw new InvalidOperationException("The dependency resolution graph contains duplicate package identities.");
        var children = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var queue = new Queue<string>();
        foreach (var edge in edges)
        {
            var child = DependencyKey(edge.Child);
            if (!known.Contains(child) || edge.Parent != null && !known.Contains(DependencyKey(edge.Parent)))
                throw new InvalidOperationException("The dependency resolution graph references a package outside the report.");
            if (edge.Parent == null)
            {
                queue.Enqueue(child);
                continue;
            }
            var parent = DependencyKey(edge.Parent);
            if (!children.TryGetValue(parent, out var siblings))
                children[parent] = siblings = [];
            siblings.Add(child);
        }
        var reachable = new HashSet<string>(StringComparer.Ordinal);
        while (queue.TryDequeue(out var key))
        {
            if (!reachable.Add(key)) continue;
            if (children.TryGetValue(key, out var next))
                foreach (var child in next) queue.Enqueue(child);
        }
        if (reachable.Count != known.Count)
            throw new InvalidOperationException("The dependency resolution graph contains packages with no introduction path from a direct dependency.");
    }

    private static string DependencyKey(Dependency dependency) =>
        $"{dependency.Ecosystem}\n{(dependency.Ecosystem == "nuget" ? dependency.Name.ToLowerInvariant() : dependency.Name)}\n" +
        $"{dependency.Version}\n{dependency.Source}\n{dependency.Sha256.ToLowerInvariant()}";

}
