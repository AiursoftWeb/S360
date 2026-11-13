using System.Security.Cryptography;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public interface IArtifactSourceVerifier
{
    Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default);
}

public class ArtifactSourceVerifier(IConfiguration configuration, IHttpClientFactory clients) : IArtifactSourceVerifier
{
    public async Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default)
    {
        if (!AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source)) return false;
        if (artifact.VerificationSource != null)
        {
            var upstream = MirrorPackageSources.Upstream(configuration, artifact.Ecosystem, artifact.Source);
            if (upstream == null || upstream != artifact.VerificationSource) return false;
            artifact = new PackageArtifact
            {
                Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
                Source = upstream, Sha256 = artifact.Sha256
            };
        }
        if (artifact.Ecosystem == "nuget") return await VerifyNuGetAsync(artifact, cancellationToken);
        return artifact.Ecosystem == "npm" && await VerifyNpmAsync(artifact, cancellationToken);
    }

    private async Task<bool> VerifyNpmAsync(PackageArtifact artifact, CancellationToken cancellationToken)
    {
        if (!TrustPattern.IsValidConcretePackage("npm", artifact.Name, artifact.Version)) return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        var token = deadline.Token;
        using var http = clients.CreateClient(PackageResolutionService.ArchiveClientName);
        var source = new Uri(TrustPattern.NormalizeSource(artifact.Source) + "/");
        var metadataUri = new Uri(source, Uri.EscapeDataString(artifact.Name) + "/" + Uri.EscapeDataString(artifact.Version));
        await using var metadata = await DownloadAsync(http, metadataUri, 1024 * 1024, token, "npm");
        using var document = await JsonDocument.ParseAsync(metadata, cancellationToken: token);
        var package = document.RootElement;
        if (package.GetProperty("name").GetString() != artifact.Name ||
            !DependencyScanner.NpmVersionsMatch(package.GetProperty("version").GetString(), artifact.Version)) return false;
        if (!Uri.TryCreate(package.GetProperty("dist").GetProperty("tarball").GetString(), UriKind.Absolute, out var uri) ||
            !SameOrigin(source, uri) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        // Verify this archive directly, like NuGet. Resolving its dependencies here
        // would reject other-platform optional packages and repeatedly install entire trees.
        await using var archive = await DownloadAsync(http, uri, 512L * 1024 * 1024, token, "npm");
        var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, token));
        if (!hash.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase)) return false;
        archive.Position = 0;
        await DependencyScanner.ValidateNpmArchiveIdentityAsync(archive, artifact.Name, artifact.Version,
            $"{artifact.Name}@{artifact.Version}", token);
        return true;
    }

    private async Task<bool> VerifyNuGetAsync(PackageArtifact artifact, CancellationToken cancellationToken)
    {
        if (!TrustPattern.IsValidConcretePackage("nuget", artifact.Name, artifact.Version)) return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(5));
        var token = deadline.Token;
        using var http = clients.CreateClient(PackageResolutionService.ArchiveClientName);
        var source = new Uri(TrustPattern.NormalizeSource(artifact.Source));
        await using var index = await DownloadAsync(http, source, 1024 * 1024, token);
        using var document = await JsonDocument.ParseAsync(index, cancellationToken: token);
        var resource = document.RootElement.GetProperty("resources").EnumerateArray().First(item =>
            item.GetProperty("@type").GetString() == "PackageBaseAddress/3.0.0");
        var baseAddress = new Uri(TrustPattern.NormalizeSource(resource.GetProperty("@id").GetString()!) + "/");
        // The selected registry must serve the archive itself. Do not follow an
        // index or redirect to an unrelated origin during independent verification.
        if (!SameOrigin(source, baseAddress)) return false;
        var name = artifact.Name.ToLowerInvariant();
        var version = NormalizeVersion(artifact.Version);
        var uri = new Uri(baseAddress, $"{name}/{version}/{name}.{version}.nupkg");
        await using var archive = await DownloadAsync(http, uri, 512L * 1024 * 1024, token);
        var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, token));
        if (!hash.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase)) return false;
        archive.Position = 0;
        DependencyScanner.ValidateNuGetArchiveIdentity(archive, artifact.Name, artifact.Version,
            $"{artifact.Name}/{artifact.Version}");
        return true;
    }

    private static string NormalizeVersion(string version)
    {
        var parts = version.Split('+', 2)[0].ToLowerInvariant().Split('-', 2);
        var numbers = parts[0].Split('.').Select(int.Parse).ToList();
        while (numbers.Count < 3) numbers.Add(0);
        if (numbers.Count == 4 && numbers[3] == 0) numbers.RemoveAt(3);
        return string.Join('.', numbers) + (parts.Length == 2 ? "-" + parts[1] : "");
    }

    private static bool SameOrigin(Uri first, Uri second) =>
        second.Scheme == Uri.UriSchemeHttps &&
        first.GetLeftPart(UriPartial.Authority).Equals(second.GetLeftPart(UriPartial.Authority),
            StringComparison.OrdinalIgnoreCase);

    private static async Task<FileStream> DownloadAsync(HttpClient http, Uri uri, long limit, CancellationToken token,
        string ecosystem = "NuGet")
    {
        using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        if (!SameOrigin(uri, response.RequestMessage?.RequestUri ?? uri))
            throw new InvalidOperationException($"{ecosystem} content was served from a different source.");
        if (response.Content.Headers.ContentLength > limit)
            throw new InvalidOperationException($"{ecosystem} content exceeds the download limit.");
        var saved = new FileStream(Path.Combine(Path.GetTempPath(), "s360-archive-" + Guid.NewGuid().ToString("N")),
            FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024,
            FileOptions.Asynchronous | FileOptions.DeleteOnClose);
        try
        {
            await using var content = await response.Content.ReadAsStreamAsync(token);
            var buffer = new byte[64 * 1024];
            long size = 0;
            int read;
            while ((read = await content.ReadAsync(buffer, token)) != 0)
            {
                size += read;
                if (size > limit) throw new InvalidOperationException($"{ecosystem} content exceeds the download limit.");
                await saved.WriteAsync(buffer.AsMemory(0, read), token);
            }
            saved.Position = 0;
            return saved;
        }
        catch
        {
            await saved.DisposeAsync();
            throw;
        }
    }
}
