using System.IO.Compression;
using System.Net;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Tests;

[TestClass]
public class OsvWildcardFeedTests
{
    [TestMethod]
    public async Task DiscoversNeverDownloadedPackageAndRevisitsWithdrawnHistory()
    {
        using var http = new HttpClient(new ArchiveHandler(CreateArchive()));
        var feed = new OsvWildcardFeed(http);
        var rules = new[]
        {
            new TrustRule { Ecosystem = "npm", PackagePattern = "@example/*", Version = "*" }
        };
        var known = new[]
        {
            new OsvKnownAdvisory("npm", "@example/old", "GHSA-old-1111-2222")
        };

        var result = await feed.QueryAsync("npm", rules, known);

        Assert.HasCount(2, result);
        Assert.AreEqual("GHSA-new-1111-2222", result["@example/new"].Single().Id);
        Assert.IsTrue(result["@example/old"].Single().Withdrawn);
        Assert.IsFalse(result.ContainsKey("unrelated"));
    }

    [TestMethod]
    public async Task NoWildcardRuleDoesNotDownloadTheEcosystemArchive()
    {
        using var http = new HttpClient(new ArchiveHandler([]));
        var result = await new OsvWildcardFeed(http).QueryAsync("npm", [], []);
        Assert.IsEmpty(result);
    }

    private static byte[] CreateArchive()
    {
        using var bytes = new MemoryStream();
        using (var zip = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
        {
            Add(zip, "new.json", """
                {"id":"GHSA-new-1111-2222","modified":"2026-09-24T00:00:00Z",
                 "affected":[{"package":{"ecosystem":"npm","name":"@example/new"},
                 "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.1"}]}]}]}
                """);
            Add(zip, "old.json", """
                {"id":"GHSA-old-1111-2222","modified":"2026-09-24T00:00:00Z",
                 "withdrawn":"2026-09-24T00:00:00Z","affected":[]}
                """);
            Add(zip, "other.json", """
                {"id":"GHSA-other-1111-2222","modified":"2026-09-24T00:00:00Z",
                 "affected":[{"package":{"ecosystem":"npm","name":"unrelated"}}]}
                """);
        }
        return bytes.ToArray();
    }

    private static void Add(ZipArchive zip, string name, string contents)
    {
        using var writer = new StreamWriter(zip.CreateEntry(name).Open());
        writer.Write(contents);
    }

    private sealed class ArchiveHandler(byte[] archive) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.AreEqual("https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip",
                request.RequestUri?.AbsoluteUri);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(archive)
            });
        }
    }
}
