using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public static class ReportFingerprint
{
    public static string Compute(DependencyApplication application, ResolutionReport report)
    {
        ValidateReportScope(application, report.Dependencies);
        ValidateRequestedRoots(application, report.Edges.Where(e => e.Parent == null).Select(e => e.Child));
        return Compute(application.Ecosystem, application.Source, report.Context, report.Dependencies, report.Edges);
    }

    public static string ComputePersisted(DependencyApplication application)
    {
        if (application.Packages.Count == 0 || application.Edges.Count == 0 ||
            application.Packages.Any(p => p.PackageArtifact == null || p.PackageArtifact.Id != p.PackageArtifactId) ||
            application.Packages.Select(p => p.PackageArtifactId).Distinct().Count() != application.Packages.Count)
            throw new InvalidOperationException("The saved dependency report is incomplete.");

        var artifacts = application.Packages.ToDictionary(p => p.PackageArtifactId,
            p => p.PackageArtifact!);
        var dependencies = artifacts.ToDictionary(pair => pair.Key, pair => new Dependency
        {
            Ecosystem = pair.Value.Ecosystem, Name = pair.Value.Name, Version = pair.Value.Version,
            Source = pair.Value.Source, Sha256 = pair.Value.Sha256
        });
        var edges = new List<ResolutionEdge>();
        var directIds = new HashSet<int>();
        foreach (var edge in application.Edges)
        {
            if (!dependencies.TryGetValue(edge.ChildPackageId, out var child) ||
                edge.ParentPackageId.HasValue && !dependencies.ContainsKey(edge.ParentPackageId.Value))
                throw new InvalidOperationException("The saved dependency report references an unknown package.");
            if (edge.ParentPackageId == null) directIds.Add(edge.ChildPackageId);
            edges.Add(new ResolutionEdge(edge.ParentPackageId.HasValue ? dependencies[edge.ParentPackageId.Value] : null, child));
        }
        if (application.Packages.Any(p => p.IsDirect != directIds.Contains(p.PackageArtifactId)))
            throw new InvalidOperationException("The saved dependency report has inconsistent direct packages.");
        ValidateReportScope(application, dependencies.Values);
        ValidateRequestedRoots(application, directIds.Select(id => dependencies[id]));
        return Compute(application.Ecosystem, application.Source, application.ResolutionContext,
            dependencies.Values.ToList(), edges);
    }

    private static void ValidateReportScope(DependencyApplication application, IEnumerable<Dependency> dependencies)
    {
        if (dependencies.Any(d => d.Ecosystem != application.Ecosystem || d.Source != application.Source))
            throw new InvalidOperationException("The dependency report contains a package outside the requested ecosystem or source.");
    }

    private static void ValidateRequestedRoots(DependencyApplication application, IEnumerable<Dependency> roots)
    {
        List<DirectPackage?>? requested;
        try
        {
            requested = JsonSerializer.Deserialize<List<DirectPackage?>>(application.DirectPackages);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException("The request's direct dependencies are invalid.");
        }
        if (requested is not { Count: > 0 and <= 20 } ||
            requested.Any(p => p is null || string.IsNullOrWhiteSpace(p.Name) || string.IsNullOrWhiteSpace(p.Version)))
            throw new InvalidOperationException("The request's direct dependencies are missing or invalid.");

        string RootKey(string name, string version) =>
            $"{(application.Ecosystem == "nuget" ? name.ToLowerInvariant() : name)}\n{version}";
        var expected = requested.Select(p => RootKey(p!.Name, p.Version)).ToHashSet(StringComparer.Ordinal);
        var actualRoots = roots.ToList();
        var actual = actualRoots.Select(p => RootKey(p.Name, p.Version)).ToHashSet(StringComparer.Ordinal);
        if (expected.Count != requested.Count || actual.Count != actualRoots.Count ||
            actualRoots.Any(p => p.Ecosystem != application.Ecosystem) || !expected.SetEquals(actual))
            throw new InvalidOperationException("The dependency report's direct packages do not match the request.");
    }

    private static string Compute(string ecosystem, string source, string context,
        IReadOnlyCollection<Dependency> dependencies, IReadOnlyCollection<ResolutionEdge> edges)
    {
        PackageResolutionService.ValidateGraph(dependencies, edges);
        var nodes = dependencies.Select(Key).OrderBy(x => x, StringComparer.Ordinal);
        var links = edges.Select(e => $"{(e.Parent == null ? "ROOT" : Key(e.Parent))}->{Key(e.Child)}")
            .OrderBy(x => x, StringComparer.Ordinal);
        var content = $"{ecosystem}\n{source}\n{context}\n" +
                      string.Join('\n', nodes) + "\n" + string.Join('\n', links);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
    }

    private static string Key(Dependency dependency) =>
        $"{dependency.Ecosystem}\n{(dependency.Ecosystem == "nuget" ? dependency.Name.ToLowerInvariant() : dependency.Name)}\n" +
        $"{dependency.Version}\n{dependency.Source}\n{dependency.Sha256.ToLowerInvariant()}";
}
