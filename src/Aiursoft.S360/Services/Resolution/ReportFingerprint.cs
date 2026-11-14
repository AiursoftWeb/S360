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
        var direct = report.Edges.Where(e => e.Parent == null).Select(e => e.Child).ToList();
        ValidateRequestedRoots(application, direct);
        return Compute(application.Ecosystem, application.Source, report.Context,
            report.Dependencies, direct);
    }

    public static string ComputePersisted(DependencyApplication application)
    {
        if (!application.Packages.Any() ||
            application.Packages.Any(p => p.PackageVersion == null || p.PackageVersion.Id != p.PackageVersionId) ||
            application.Packages.Select(p => p.PackageVersionId).Distinct().Count() != application.Packages.Count())
            throw new InvalidOperationException("The saved dependency report is incomplete.");
        Dependency Read(ApplicationPackage p) => new()
        {
            Ecosystem = p.PackageVersion.Ecosystem,
            Name = p.PackageVersion.Name,
            Version = p.PackageVersion.Version,
            Source = p.PackageVersion.Source
        };
        var dependencies = application.Packages.Select(Read).ToList();
        var direct = application.Packages.Where(p => p.IsDirect).Select(Read).ToList();
        ValidateReportScope(application, dependencies);
        ValidateRequestedRoots(application, direct);
        return Compute(application.Ecosystem, application.Source, application.ResolutionContext,
            dependencies, direct);
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
        IReadOnlyCollection<Dependency> dependencies, IReadOnlyCollection<Dependency> direct)
    {
        // This fingerprints the review text, never package files. Historical request
        // reports keep their original fingerprint; new reviews bind the current list.
        var nodes = dependencies.Select(Key).OrderBy(x => x, StringComparer.Ordinal);
        var roots = direct.Select(Key).OrderBy(x => x, StringComparer.Ordinal);
        var content = $"{ecosystem}\n{source}\n{context}\n" +
                      string.Join('\n', nodes) + "\n" + string.Join('\n', roots);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
    }

    private static string Key(Dependency dependency) =>
        $"{dependency.Ecosystem}\n{(dependency.Ecosystem == "nuget" ? dependency.Name.ToLowerInvariant() : dependency.Name)}\n" +
        $"{dependency.Version}\n{dependency.Source}";
}
