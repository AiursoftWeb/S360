using System.Net;
using Aiursoft.S360.Services.AlertMonitoring;

namespace Aiursoft.S360.Tests;

[TestClass]
public class GitLabBaselineLifecycleTests
{
    private const string Missing = "aiursoft/wechatexamv2";
    private const string Archived = "aiursoft/baget";
    private const string Live = "aiursoft/live";

    [TestMethod]
    public async Task RepeatedVerifiedAbsenceRetiresOnlyMissingPathAndRestorationResumesIt()
    {
        var handler = new GitLabHandler();
        var clock = new TestClock();
        var lifecycle = Create(handler, clock);

        var first = await lifecycle.ReadAsync([Missing, Archived, Live]);
        Assert.AreEqual(BaselineLifecycleStatus.Unconfirmed, first[Missing]);
        Assert.AreEqual(BaselineLifecycleStatus.Active, first[Archived]);
        Assert.AreEqual(BaselineLifecycleStatus.Active, first[Live]);
        Assert.AreEqual(1, handler.MissingLookups);

        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.AreEqual(BaselineLifecycleStatus.Unconfirmed, (await lifecycle.ReadAsync([Missing]))[Missing]);
        Assert.AreEqual(1, handler.MissingLookups);

        clock.Advance(TimeSpan.FromMinutes(4));
        Assert.AreEqual(BaselineLifecycleStatus.Retired, (await lifecycle.ReadAsync([Missing]))[Missing]);
        handler.Restored = true;
        clock.Advance(TimeSpan.FromMinutes(5));
        Assert.AreEqual(BaselineLifecycleStatus.Active, (await lifecycle.ReadAsync([Missing]))[Missing]);
    }

    [TestMethod]
    [DataRow("inventory unavailable")]
    [DataRow("truncated inventory")]
    [DataRow("lost membership")]
    [DataRow("lookup forbidden")]
    [DataRow("proxy not found")]
    [DataRow("external redirect")]
    public async Task UnreliableGitLabResultsInvalidateTheSequence(string failure)
    {
        var handler = new GitLabHandler();
        var clock = new TestClock();
        var lifecycle = Create(handler, clock);
        Assert.AreEqual(BaselineLifecycleStatus.Unconfirmed, (await lifecycle.ReadAsync([Missing]))[Missing]);

        clock.Advance(TimeSpan.FromMinutes(5));
        handler.Failure = failure;
        try
        {
            await lifecycle.ReadAsync([Missing]);
            Assert.Fail("Unreliable GitLab data should fail the scan.");
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or System.Text.Json.JsonException)
        {
            // No lifecycle states survive a failed scan.
        }
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => lifecycle.ReadAsync([Missing]));

        clock.Advance(TimeSpan.FromMinutes(5));
        handler.Failure = null;
        Assert.AreEqual(BaselineLifecycleStatus.Unconfirmed, (await lifecycle.ReadAsync([Missing]))[Missing]);
    }

    private static GitLabBaselineLifecycle Create(GitLabHandler handler, TimeProvider clock)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["BaselineGitLab:Endpoint"] = "https://gitlab.example/",
            ["BaselineGitLab:ReadToken"] = "test-token"
        }).Build();
        return new GitLabBaselineLifecycle(new TestClientFactory(handler), config, clock);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UnixEpoch;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan time) => _now += time;
    }

    private sealed class TestClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private sealed class GitLabHandler : HttpMessageHandler
    {
        public bool Restored { get; set; }
        public string? Failure { get; set; }
        public int MissingLookups { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.AreEqual("test-token", request.Headers.GetValues("PRIVATE-TOKEN").Single());
            var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            var response = path switch
            {
                "/api/v4/user" => Json(new { id = 27 }),
                "/api/v4/groups/aiursoft" => Json(new { id = 5, full_path = "aiursoft" }),
                "/api/v4/groups/5/members/all/27" => Json(new
                {
                    id = 27, access_level = Failure == "lost membership" ? 10 : 20, state = "active"
                }),
                "/api/v4/groups/5/projects" => Inventory(request.RequestUri.Query.Contains("archived=true", StringComparison.Ordinal)),
                "/api/v4/projects/" + Archived => Redirect("https://gitlab.example/api/v4/projects/11"),
                "/api/v4/projects/11" => Json(new { id = 11, path_with_namespace = Archived, archived = true }),
                "/api/v4/projects/" + Missing => LookupMissing(),
                _ => throw new InvalidOperationException("Unexpected GitLab request.")
            };
            return Task.FromResult(response);
        }

        private HttpResponseMessage LookupMissing()
        {
            MissingLookups++;
            if (Restored) return Json(new { id = 585, path_with_namespace = Missing });
            if (Failure == "external redirect") return Redirect("https://other.example/api/v4/projects/585");
            if (Failure == "lookup forbidden") return new HttpResponseMessage(HttpStatusCode.Forbidden);
            if (Failure == "proxy not found") return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("<h1>404</h1>") };
            return Json(new { message = "404 Project Not Found" }, HttpStatusCode.NotFound);
        }

        private HttpResponseMessage Inventory(bool archived)
        {
            if (Failure == "inventory unavailable") return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            var response = archived ? Json(Array.Empty<object>()) : Json(new[] { new { id = 1, path_with_namespace = Live } });
            response.Headers.TryAddWithoutValidation("X-Page", "1");
            response.Headers.TryAddWithoutValidation("X-Total", archived ? "0" : Failure == "truncated inventory" ? "2" : "1");
            response.Headers.TryAddWithoutValidation("X-Next-Page", "");
            return response;
        }

        private static HttpResponseMessage Redirect(string url)
        {
            var response = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            response.Headers.Location = new Uri(url);
            return response;
        }

        private static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
            new(status) { Content = JsonContent.Create(value) };
    }
}
