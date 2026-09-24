using Aiursoft.S360.Entities;

namespace Aiursoft.S360.Services.Resolution;

public interface IArtifactSourceVerifier
{
    Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default);
}

public class ArtifactSourceVerifier(PackageResolutionService resolver, IConfiguration configuration) : IArtifactSourceVerifier
{
    public async Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default)
    {
        if (!AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source)) return false;
        var report = await resolver.ResolveAsync(artifact.Ecosystem, artifact.Source,
            [new DirectPackage(artifact.Name, artifact.Version)], cancellationToken);
        var direct = report.Edges.Where(edge => edge.Parent == null).Select(edge => edge.Child).Single();
        return direct.Ecosystem == artifact.Ecosystem &&
               direct.Name.Equals(artifact.Name, artifact.Ecosystem == "nuget"
                   ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
               direct.Version.Equals(artifact.Version, StringComparison.OrdinalIgnoreCase) &&
               direct.Source == artifact.Source &&
               direct.Sha256.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase);
    }
}
