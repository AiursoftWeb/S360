using System.IO.Compression;
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
            ["SupplyChain:NuGetSources:0"] = "https://nuget.example.com/index.json"
        }).Build();
        var factory = new ArchiveClientFactory(handler);
        return new ArtifactSourceVerifier(new PackageResolutionService(factory), configuration, factory);
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
