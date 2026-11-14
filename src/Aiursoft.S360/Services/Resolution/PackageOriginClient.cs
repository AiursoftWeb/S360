using Aiursoft.Scanner.Abstractions;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public sealed record PackageSourceOrigin(string Ecosystem, string Name, string Version, string Mode, string? Sha256, string? Archive);

public class PackageOriginClient(IConfiguration configuration, IHttpClientFactory clients) : IScopedDependency
{
    public async Task<PackageSourceOrigin?> GetAsync(string ecosystem, string name, string version, string source,
        CancellationToken token = default)
    {
        if (!AllowedPackageSources.Contains(configuration, ecosystem, source)) return null;
        var mapping = (configuration.GetSection("SupplyChain:Mirrors").Get<MirrorPackageSource[]>() ?? [])
            .SingleOrDefault(m => m.Ecosystem == ecosystem && TrustPattern.NormalizeSource(m.Source) == TrustPattern.NormalizeSource(source));
        if (mapping?.OriginEndpoint == null) return null;
        var registry = new Uri(source);
        if (MirrorPackageSources.Upstream(configuration, ecosystem, source) == null ||
            !Uri.TryCreate(mapping.OriginEndpoint, UriKind.Absolute, out var endpoint) ||
            !SameOrigin(registry, endpoint) || endpoint.Query.Length != 0)
            throw new InvalidOperationException("Invalid package origin endpoint configuration.");
        if (!TrustPattern.IsValidConcretePackage(ecosystem, name, version))
            throw new InvalidOperationException("Invalid package identity for origin verification.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        token = deadline.Token;
        var uri = new UriBuilder(endpoint) { Query = "name=" + Uri.EscapeDataString(name) + "&version=" + Uri.EscapeDataString(version) }.Uri;
        using var http = clients.CreateClient(PackageResolutionService.ArchiveClientName);
        using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        if (!SameOrigin(endpoint, response.RequestMessage?.RequestUri ?? endpoint) || response.Content.Headers.ContentLength > 16384)
            throw new InvalidDataException("Invalid package origin response.");
        // Bound the complete body even when a peer does not send Content-Length.
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var data = new MemoryStream();
        var buffer = new byte[4096];
        int read;
        while ((read = await input.ReadAsync(buffer, token)) != 0)
        {
            if (data.Length + read > 16384) throw new InvalidDataException("Package origin response is too large.");
            data.Write(buffer, 0, read);
        }
        var origin = System.Text.Json.JsonSerializer.Deserialize<PackageSourceOrigin>(data.ToArray(), System.Text.Json.JsonSerializerOptions.Web);
        if (origin == null || origin.Ecosystem != ecosystem ||
            !string.Equals(origin.Name, name, ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ||
            !TrustPattern.IsValidConcretePackage(ecosystem, origin.Name, origin.Version) ||
            !(ecosystem == "nuget" ? ArtifactSourceVerifier.NormalizeVersion(origin.Version) == ArtifactSourceVerifier.NormalizeVersion(version)
                : origin.Version == version) || origin.Mode is not ("local" or "mirror") ||
            (origin.Mode == "mirror" && (origin.Sha256 != null || origin.Archive != null)))
            throw new InvalidDataException("Package origin does not describe the requested identity.");
        if (origin.Mode == "local" && (origin.Sha256 != null || origin.Archive != null) &&
            (origin.Sha256 is not { Length: 64 } || !origin.Sha256.All(Uri.IsHexDigit) || origin.Archive == null ||
             !SameOrigin(registry, new Uri(registry, origin.Archive))))
            throw new InvalidDataException("Invalid local archive evidence.");
        return origin;
    }

    internal static bool SameOrigin(Uri first, Uri second) => second.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(second.UserInfo) && string.IsNullOrEmpty(second.Fragment) &&
        first.GetLeftPart(UriPartial.Authority).Equals(second.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase);
}
