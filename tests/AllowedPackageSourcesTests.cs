using System.IO.Compression;
using System.Formats.Tar;
using System.Text.Json;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Resolution;

namespace Aiursoft.S360.Tests;

[TestClass]
public class AllowedPackageSourcesTests
{
    [TestMethod]
    [DataRow("nuget", true)]
    [DataRow("npm", true)]
    [DataRow("nuget", false)]
    [DataRow("npm", false)]
    public async Task InternalDistributionVerificationUsesOnlyTheConfiguredUpstream(string ecosystem, bool explicitSource)
    {
        var source = "https://internal.example/index.json";
        var upstream = ecosystem == "nuget" ? "https://nuget.example.com/index.json" : "https://npm.example.com";
        using var nuget = new NuGetHandler(Archive("Android.Widget", "1.2.3"));
        using var npm = new NpmHandler("@example/arm64", "1.2.3");
        var bytes = ecosystem == "nuget" ? nuget.ArchiveBytes : npm.Bytes;
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"SupplyChain:{(ecosystem == "nuget" ? "NuGet" : "Npm")}Sources:0"] = source,
            ["SupplyChain:Mirrors:0:Ecosystem"] = ecosystem,
            ["SupplyChain:Mirrors:0:Source"] = source,
            ["SupplyChain:Mirrors:0:Upstream"] = upstream
        }).Build();
        var verifier = new ArtifactSourceVerifier(configuration, new ArchiveClientFactory(ecosystem == "nuget" ? nuget : npm));
        var artifact = new PackageArtifact { Ecosystem = ecosystem,
            Name = ecosystem == "nuget" ? "Android.Widget" : "@example/arm64", Version = "1.2.3",
            Source = source, Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)), VerificationSource = explicitSource ? upstream : null };
        Assert.IsTrue(await verifier.VerifyAsync(artifact));
        Assert.AreEqual(upstream, artifact.VerificationSource);
        artifact.VerificationSource = null;
        artifact.Sha256 = new string('0', 64);
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
        Assert.IsNull(artifact.VerificationSource, "A failed download verification must not bind its source.");
        artifact.VerificationSource = "https://caller-selected.example";
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
        configuration["SupplyChain:Mirrors:0:Upstream"] = "http://untrusted.example";
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
    }

    [TestMethod]
    public void OnlyConfiguredEcosystemSourcesAreAllowed()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SupplyChain:NuGetSources:0"] = "https://nuget.aiursoft.com/v3/index.json",
            ["SupplyChain:NpmSources:0"] = "https://npm.aiursoft.com"
        }).Build();

        Assert.IsTrue(AllowedPackageSources.Contains(configuration, "nuget",
            "https://nuget.aiursoft.com/v3/index.json"));
        Assert.IsTrue(AllowedPackageSources.Contains(configuration, "npm", "https://npm.aiursoft.com/"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "nuget", "https://npm.aiursoft.com"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "npm", "https://127.0.0.1"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "other", "https://nuget.aiursoft.com/v3/index.json"));
    }

    [TestMethod]
    [DataRow("Android.Widget", "1.2.3", "1.2.3", "1.2.3", true)]
    [DataRow("android.widget", "1.2.3", "1.2.3", "1.2.3", true)]
    [DataRow("Android.Widget", "1.2.0", "1.2", "1.2.0", true)]
    [DataRow("Android.Widget", "1.2.3.0", "1.2.3+build", "1.2.3", true)]
    [DataRow("Different.Package", "1.2.3", "1.2.3", "1.2.3", false)]
    [DataRow("Android.Widget", "9.0.0", "1.2.3", "1.2.3", false)]
    public async Task NuGetSourceVerificationChecksArchiveIdentityWithoutRestoringAFramework(
        string archiveName, string archiveVersion, string version, string normalizedVersion, bool matches)
    {
        using var handler = new NuGetHandler(Archive(archiveName, archiveVersion));
        var verifier = CreateVerifier(handler);
        var artifact = Artifact(handler.ArchiveBytes, version);
        if (matches) Assert.IsTrue(await verifier.VerifyAsync(artifact));
        else await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => verifier.VerifyAsync(artifact));
        Assert.AreEqual(2, handler.Requests);
        Assert.AreEqual($"https://nuget.example.com/packages/android.widget/{normalizedVersion}/android.widget.{normalizedVersion}.nupkg",
            handler.LastUri?.AbsoluteUri);
    }

    [TestMethod]
    public async Task NuGetSourceVerificationRejectsHashAndSourceMismatch()
    {
        using var handler = new NuGetHandler(Archive("Android.Widget", "1.2.3"));
        var verifier = CreateVerifier(handler);
        var artifact = Artifact(handler.ArchiveBytes);
        artifact.Sha256 = new string('0', 64);
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
        artifact.Source = "https://unapproved.example.com/index.json";
        var previous = handler.Requests;
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
        Assert.AreEqual(previous, handler.Requests);
        artifact.Source = "https://nuget.example.com/index.json";
        handler.BaseAddress = "https://unapproved.example.com/packages/";
        Assert.IsFalse(await verifier.VerifyAsync(artifact));
        Assert.AreEqual(previous + 1, handler.Requests);
    }

    [TestMethod]
    [DataRow(302)]
    [DataRow(404)]
    public async Task NuGetSourceVerificationRejectsRedirectsAndMissingArchives(int status)
    {
        using var handler = new NuGetHandler(Archive("Android.Widget", "1.2.3"));
        handler.ArchiveStatus = (HttpStatusCode)status;
        await Assert.ThrowsExactlyAsync<HttpRequestException>(() => CreateVerifier(handler).VerifyAsync(Artifact(handler.ArchiveBytes)));
    }

    [TestMethod]
    [DataRow("sample", "1.2.3", false)]
    [DataRow("@example/arm64", "1.2.3", false)]
    [DataRow("@example/arm64", "1.2.3-beta.1", false)]
    [DataRow("sample", "1.2.3", true)]
    [DataRow("@example/arm64", "1.2.3-beta.1", true)]
    public async Task NpmSourceVerificationChecksSingleArchiveWithoutInstallingOtherPlatformPackages(string name, string version, bool legacyPrefix)
    {
        using var handler = new NpmHandler(name, version);
        if (legacyPrefix)
        {
            handler.Bytes = NpmArchive(name, "v" + version);
            handler.MetadataVersion = "v" + version;
        }
        Assert.IsTrue(await CreateVerifier(handler).VerifyAsync(handler.Artifact()));
        Assert.AreEqual(2, handler.Requests);
        StringAssert.Contains(handler.MetadataUri!.AbsoluteUri, Uri.EscapeDataString(name));
    }

    [TestMethod]
    [DataRow("hash")]
    [DataRow("metadata-name")]
    [DataRow("metadata-version")]
    [DataRow("archive-name")]
    [DataRow("source")]
    [DataRow("tarball-source")]
    [DataRow("redirect")]
    [DataRow("missing")]
    public async Task NpmSourceVerificationRejectsChangedOrUnapprovedArchives(string failure)
    {
        using var handler = new NpmHandler("@example/arm64", "1.2.3");
        var artifact = handler.Artifact();
        if (failure == "hash") artifact.Sha256 = new string('0', 64);
        if (failure == "source") artifact.Source = "https://unapproved.example.com";
        if (failure == "metadata-name") handler.MetadataName = "different";
        if (failure == "metadata-version") handler.MetadataVersion = "9.0.0";
        if (failure == "archive-name") handler.Bytes = NpmArchive("different", "1.2.3");
        if (failure == "archive-name") artifact.Sha256 = Convert.ToHexStringLower(SHA256.HashData(handler.Bytes));
        if (failure == "tarball-source") handler.Tarball = "https://unapproved.example.com/package.tgz";
        if (failure == "redirect") handler.ArchiveStatus = HttpStatusCode.Redirect;
        if (failure == "missing") handler.ArchiveStatus = HttpStatusCode.NotFound;
        var verifier = CreateVerifier(handler);
        if (failure is "redirect" or "missing")
            await Assert.ThrowsExactlyAsync<HttpRequestException>(() => verifier.VerifyAsync(artifact));
        else if (failure == "archive-name")
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => verifier.VerifyAsync(artifact));
        else Assert.IsFalse(await verifier.VerifyAsync(artifact));
        if (failure == "source") Assert.AreEqual(0, handler.Requests);
        if (failure == "tarball-source") Assert.AreEqual(1, handler.Requests);
    }

    [TestMethod]
    [DataRow("nuget")]
    [DataRow("npm")]
    public async Task LocalOriginVerifiesInternalBytesInsteadOfTheOfficialMirror(string ecosystem)
    {
        using var handler = new LocalOriginHandler(ecosystem);
        var configuration = LocalOriginConfiguration(ecosystem);
        var factory = new ArchiveClientFactory(handler);
        var verifier = new ArtifactSourceVerifier(configuration, factory);
        var artifact = handler.Artifact();
        artifact.VerificationSource = "https://official.example";
        Assert.IsTrue(await verifier.VerifyAsync(artifact));
        Assert.AreEqual("https://internal.example", artifact.VerificationSource);
        Assert.AreEqual(1, handler.ArchiveRequests);
        Assert.AreEqual(2, handler.OriginRequests, "Origin must be checked again after the download.");

    }

    [TestMethod]
    [DataRow("nuget", "hash")]
    [DataRow("npm", "hash")]
    [DataRow("nuget", "identity")]
    [DataRow("npm", "identity")]
    [DataRow("nuget", "missing")]
    [DataRow("npm", "missing")]
    [DataRow("nuget", "redirect")]
    [DataRow("npm", "redirect")]
    [DataRow("nuget", "changed-mode")]
    [DataRow("npm", "changed-mode")]
    [DataRow("nuget", "unavailable")]
    [DataRow("npm", "unavailable")]
    public async Task LocalOriginRejectsInvalidOrChangedEvidence(string ecosystem, string failure)
    {
        using var handler = new LocalOriginHandler(ecosystem) { Failure = failure };
        var configuration = LocalOriginConfiguration(ecosystem);
        var verifier = new ArtifactSourceVerifier(configuration, new ArchiveClientFactory(handler));
        var artifact = handler.Artifact();
        if (failure is "redirect" or "identity")
            await Assert.ThrowsExactlyAsync<InvalidDataException>(() => verifier.VerifyAsync(artifact));
        else if (failure == "unavailable")
            await Assert.ThrowsExactlyAsync<HttpRequestException>(() => verifier.VerifyAsync(artifact));
        else Assert.IsFalse(await verifier.VerifyAsync(artifact));
        Assert.IsNull(artifact.VerificationSource);
    }

    private static IConfiguration LocalOriginConfiguration(string ecosystem) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"SupplyChain:{(ecosystem == "nuget" ? "NuGet" : "Npm")}Sources:0"] = "https://internal.example",
            ["SupplyChain:Mirrors:0:Ecosystem"] = ecosystem,
            ["SupplyChain:Mirrors:0:Source"] = "https://internal.example",
            ["SupplyChain:Mirrors:0:Upstream"] = "https://official.example",
            ["SupplyChain:Mirrors:0:OriginEndpoint"] = "https://internal.example/api/package-origins"
        }).Build();

    private sealed class LocalOriginHandler(string ecosystem) : HttpMessageHandler
    {
        private readonly byte[] _bytes = ecosystem == "nuget" ? Archive("sample", "1.0.0") : NpmArchive("sample", "1.0.0");
        public string? Failure { get; init; }
        public int ArchiveRequests { get; private set; }
        public int OriginRequests { get; private set; }
        public PackageArtifact Artifact() => new() { Ecosystem = ecosystem, Name = "sample", Version = "1.0.0",
            Source = "https://internal.example", Sha256 = Convert.ToHexStringLower(SHA256.HashData(_bytes)) };
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Assert.AreEqual("internal.example", request.RequestUri!.Host, "Locally owned packages must never contact upstream.");
            if (request.RequestUri.AbsolutePath == "/api/package-origins")
            {
                OriginRequests++;
                var missing = Failure == "missing";
                var changed = Failure == "changed-mode" && OriginRequests > 1;
                var proof = new PackageSourceOrigin(ecosystem, Failure == "identity" ? "different" : "sample", "1.0.0",
                    changed ? "mirror" : "local", missing || changed ? null : Artifact().Sha256,
                    missing || changed ? null : Failure == "redirect" ? "https://other.example/archive" : "/archive");
                return Task.FromResult(new HttpResponseMessage(Failure == "unavailable" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK)
                    { RequestMessage = request, Content = JsonContent.Create(proof) });
            }
            ArchiveRequests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request,
                Content = new ByteArrayContent(Failure == "hash" ? [1, 2, 3] : _bytes) });
        }
    }

    private static byte[] NpmArchive(string name, string version)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionMode.Compress, leaveOpen: true))
        using (var tar = new TarWriter(gzip))
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                name, version, os = new[] { "darwin" }, cpu = new[] { "arm64" },
                dependencies = new Dictionary<string, string> { ["must-not-be-resolved"] = "1.0.0" },
                scripts = new { install = "exit 99" }
            });
            using var content = new MemoryStream(bytes);
            tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "package/package.json") { DataStream = content });
        }
        return output.ToArray();
    }

    private sealed class NpmHandler(string name, string version) : HttpMessageHandler
    {
        private string OriginalName { get; } = name;
        private string OriginalVersion { get; } = version;
        public byte[] Bytes { get; set; } = NpmArchive(name, version);
        public string MetadataName { get; set; } = name;
        public string MetadataVersion { get; set; } = version;
        public string Tarball { get; set; } = "https://npm.example.com/package.tgz";
        public HttpStatusCode ArchiveStatus { get; set; } = HttpStatusCode.OK;
        public int Requests { get; private set; }
        public Uri? MetadataUri { get; private set; }
        public PackageArtifact Artifact() => new()
        {
            Ecosystem = "npm", Name = OriginalName, Version = OriginalVersion, Source = "https://npm.example.com",
            Sha256 = Convert.ToHexStringLower(SHA256.HashData(Bytes))
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            var archive = request.RequestUri!.AbsolutePath == "/package.tgz";
            if (!archive) MetadataUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(archive ? ArchiveStatus : HttpStatusCode.OK)
            {
                RequestMessage = request,
                Content = archive ? new ByteArrayContent(Bytes) : new StringContent(JsonSerializer.Serialize(new
                {
                    name = MetadataName, version = MetadataVersion, dist = new { tarball = Tarball }
                }))
            });
        }
    }

    private static PackageArtifact Artifact(byte[] archive, string version = "1.2.3") => new()
    {
        Ecosystem = "nuget", Name = "Android.Widget", Version = version,
        Source = "https://nuget.example.com/index.json",
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(archive))
    };

    private static ArtifactSourceVerifier CreateVerifier(HttpMessageHandler handler)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SupplyChain:NuGetSources:0"] = "https://nuget.example.com/index.json",
            ["SupplyChain:NpmSources:0"] = "https://npm.example.com"
        }).Build();
        var factory = new ArchiveClientFactory(handler);
        return new ArtifactSourceVerifier(configuration, factory);
    }

    private static byte[] Archive(string name, string version)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        using (var manifest = new StreamWriter(zip.CreateEntry($"{name}.nuspec").Open(), Encoding.UTF8))
            manifest.Write($"""
                <package><metadata><id>{name}</id><version>{version}</version>
                <dependencies><group targetFramework="net10.0-android36.0" /></dependencies>
                </metadata></package>
                """);
        return output.ToArray();
    }

    private sealed class ArchiveClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class NuGetHandler(byte[] archive) : HttpMessageHandler
    {
        public byte[] ArchiveBytes => archive;
        public string BaseAddress { get; set; } = "https://nuget.example.com/packages/";
        public HttpStatusCode ArchiveStatus { get; set; } = HttpStatusCode.OK;
        public int Requests { get; private set; }
        public Uri? LastUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            LastUri = request.RequestUri;
            var index = request.RequestUri!.AbsolutePath == "/index.json";
            var response = new HttpResponseMessage(index ? HttpStatusCode.OK : ArchiveStatus)
            {
                RequestMessage = request,
                Content = index
                    ? new StringContent($$"""{"resources":[{"@type":"PackageBaseAddress/3.0.0","@id":"{{BaseAddress}}"}]}""")
                    : new ByteArrayContent(archive)
            };
            return Task.FromResult(response);
        }
    }
}
