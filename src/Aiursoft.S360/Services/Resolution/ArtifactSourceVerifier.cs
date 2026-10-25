using System.Security.Cryptography;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public interface IArtifactSourceVerifier
{
    Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default);
}

public class ArtifactSourceVerifier(PackageResolutionService resolver, IConfiguration configuration,
    IHttpClientFactory clients) : IArtifactSourceVerifier
{
    public async Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default)
    {
        if (!AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source)) return false;
        if (artifact.Ecosystem == "nuget") return await VerifyNuGetAsync(artifact, cancellationToken);
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

    private static async Task<FileStream> DownloadAsync(HttpClient http, Uri uri, long limit, CancellationToken token)
    {
        using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token);
        response.EnsureSuccessStatusCode();
        if (!SameOrigin(uri, response.RequestMessage?.RequestUri ?? uri))
            throw new InvalidOperationException("NuGet content was served from a different source.");
        if (response.Content.Headers.ContentLength > limit)
            throw new InvalidOperationException("NuGet content exceeds the download limit.");
        var saved = new FileStream(Path.Combine(Path.GetTempPath(), "s360-nuget-" + Guid.NewGuid().ToString("N")),
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
                if (size > limit) throw new InvalidOperationException("NuGet content exceeds the download limit.");
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
