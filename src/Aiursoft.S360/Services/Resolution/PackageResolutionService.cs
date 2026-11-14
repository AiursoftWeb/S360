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
}
