using System.Globalization;
using System.Net;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Tests;

[TestClass]
public class OsvClientTests
{
    [TestMethod]
    public async Task SeparateOsvClientsShareTheRequestRateLimit()
    {
        using var throttle = new OsvRequestThrottle(new ConfigurationBuilder().Build());
        var starts = new List<long>();
        Task<HttpResponseMessage> Respond(HttpRequestMessage _)
        {
            starts.Add(Stopwatch.GetTimestamp());
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent("""{"vulns":[]}""") });
        }
        using var first = new HttpClient(new OsvRequestHandler(throttle) { InnerHandler = new CallbackHandler(Respond) });
        using var second = new HttpClient(new OsvRequestHandler(throttle) { InnerHandler = new CallbackHandler(Respond) });

        await Task.WhenAll(new OsvClient(first).QueryAsync("nuget", "First"),
            new OsvClient(second).QueryAsync("nuget", "Second"));

        Assert.HasCount(2, starts);
        Assert.IsTrue(Stopwatch.GetElapsedTime(starts[0], starts[1]) >= TimeSpan.FromMilliseconds(450));
    }

    [TestMethod]
    public async Task RateLimitedQueryRespectsRetryAfterAndPreservesItsBody()
    {
        using var throttle = new OsvRequestThrottle(new ConfigurationBuilder().Build());
        var bodies = new List<string>();
        var starts = new List<long>();
        using var http = new HttpClient(new OsvRequestHandler(throttle)
        {
            InnerHandler = new CallbackHandler(async request =>
            {
                starts.Add(Stopwatch.GetTimestamp());
                bodies.Add(await request.Content!.ReadAsStringAsync());
                Assert.AreEqual("application/json", request.Content.Headers.ContentType?.MediaType);
                var response = new HttpResponseMessage(bodies.Count == 1
                    ? HttpStatusCode.TooManyRequests : HttpStatusCode.OK)
                    { Content = new StringContent("""{"vulns":[]}""") };
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(1));
                return response;
            })
        });

        var results = await new OsvClient(http).QueryAsync("nuget", "Example", "1.0.0");

        Assert.IsEmpty(results);
        Assert.HasCount(2, bodies);
        Assert.AreEqual(bodies[0], bodies[1]);
        Assert.IsTrue(Stopwatch.GetElapsedTime(starts[0], starts[1]) >= TimeSpan.FromMilliseconds(950));
    }

    [TestMethod]
    public async Task PersistentRateLimitFailsClosedAfterTwoRetries()
    {
        using var throttle = new OsvRequestThrottle(new ConfigurationBuilder().Build());
        var attempts = 0;
        using var http = new HttpClient(new OsvRequestHandler(throttle)
        {
            InnerHandler = new CallbackHandler(_ =>
            {
                attempts++;
                var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.Zero);
                return Task.FromResult(response);
            })
        });

        var error = await Assert.ThrowsExactlyAsync<HttpRequestException>(() =>
            new OsvClient(http).QueryAsync("nuget", "Example"));

        Assert.AreEqual(HttpStatusCode.TooManyRequests, error.StatusCode);
        Assert.AreEqual(3, attempts);
    }

    [TestMethod]
    public async Task LongRetryAfterDateDefersOtherRequestsAndCanBeCancelled()
    {
        using var throttle = new OsvRequestThrottle(new ConfigurationBuilder().Build());
        var attempts = 0;
        using var http = new HttpClient(new OsvRequestHandler(throttle)
        {
            InnerHandler = new CallbackHandler(_ =>
            {
                attempts++;
                var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                response.Headers.RetryAfter = new RetryConditionHeaderValue(DateTimeOffset.UtcNow.AddMinutes(1));
                return Task.FromResult(response);
            })
        });
        await Assert.ThrowsExactlyAsync<HttpRequestException>(() => new OsvClient(http).QueryAsync("nuget", "First"));
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            new OsvClient(http).QueryAsync("nuget", "Second", cancellationToken: cancellation.Token));

        Assert.AreEqual(1, attempts);
    }

    [TestMethod]
    public async Task OtherUpstreamErrorsFailWithoutRetries()
    {
        using var throttle = new OsvRequestThrottle(new ConfigurationBuilder().Build());
        var attempts = 0;
        using var http = new HttpClient(new OsvRequestHandler(throttle)
        {
            InnerHandler = new CallbackHandler(_ =>
            {
                attempts++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            })
        });

        await Assert.ThrowsExactlyAsync<HttpRequestException>(() => new OsvClient(http).QueryAsync("nuget", "Example"));

        Assert.AreEqual(1, attempts);
    }

    [TestMethod]
    public async Task ReadsAllPagesAndPreservesGhsaAndWithdrawnState()
    {
        using var http = new HttpClient(new PageHandler());
        var results = await new OsvClient(http).QueryAsync("npm", "sample");
        Assert.AreEqual(2, results.Count);
        Assert.IsTrue(results.Any(v => v.Id == "GHSA-test-1111-2222" && v.Aliases.Count == 0));
        Assert.IsTrue(results.Any(v => v.Id == "OSV-TEST-2" && v.Withdrawn));
    }

    [TestMethod]
    public async Task RepeatedPaginationTokenFailsClosed()
    {
        using var http = new HttpClient(new RepeatHandler());
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            new OsvClient(http).QueryAsync("nuget", "Example"));
    }

    [TestMethod]
    public async Task AdvisoryLookupRejectsMismatchedId()
    {
        using var http = new HttpClient(new WrongIdHandler());
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            new OsvClient(http).GetByIdAsync("GHSA-expected-1111-2222"));
    }

    [TestMethod]
    public async Task VersionQueryPreservesAdvisoryFieldsAndAffectedRange()
    {
        var handler = new VersionedAdvisoryHandler();
        using var http = new HttpClient(handler);
        var advisory = (await new OsvClient(http).QueryAsync("npm", "lodash", "4.17.20")).Single();

        Assert.IsTrue(handler.QueriedExpectedVersion);
        Assert.AreEqual("GHSA-29mw-wpgm-hmr9", advisory.Id);
        CollectionAssert.Contains(advisory.Aliases.ToArray(), "CVE-2020-28500");
        StringAssert.Contains(advisory.Severity, "CVSS:3.1/");
        Assert.AreEqual(RangeRisk.Affected,
            OsvRangeMatcher.Intersects(advisory.AffectedJson, "npm", "lodash", "4.17.20"));
        Assert.AreEqual(RangeRisk.NotAffected,
            OsvRangeMatcher.Intersects(advisory.AffectedJson, "npm", "lodash", "4.17.21"));
    }

    [TestMethod]
    public async Task VersionBatchesAreBoundedAndDoNotApplyOneVersionsFindingToAnother()
    {
        var requests = new List<int>();
        var detail = new OsvAdvisory("KNOWN", [], "Known", "", DateTime.Parse("2026-09-23T00:00:00Z", CultureInfo.InvariantCulture).ToUniversalTime(), false, "[]");
        using var http = new HttpClient(new CallbackHandler(async request =>
        {
            Assert.AreEqual("/v1/querybatch", request.RequestUri!.AbsolutePath);
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var queries = document.RootElement.GetProperty("queries");
            requests.Add(queries.GetArrayLength());
            var results = queries.EnumerateArray().Select(q => new
            {
                vulns = int.Parse(q.GetProperty("version").GetString()!.Split('.')[2]) % 2 == 0
                    ? new object[] { new { id = detail.Id, modified = detail.ModifiedAtUtc } } : []
            });
            return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent(JsonSerializer.Serialize(new { results })) };
        }));
        var versions = Enumerable.Range(0, 1001).Select(index => ("npm", "sample", $"1.0.{index}"));
        var known = new Dictionary<(string, string), List<OsvAdvisory>> { [("npm", "sample")] = [detail] };

        var results = await new OsvClient(http).QueryVersionsAsync(versions, known);

        Assert.HasCount(1001, results);
        Assert.HasCount(11, requests);
        Assert.IsTrue(requests.All(count => count <= 100));
        foreach (var (version, advisories) in results)
            Assert.AreEqual(int.Parse(version.Version.Split('.')[2]) % 2 == 0 ? 1 : 0, advisories.Count);
    }

    [TestMethod]
    public async Task VersionBatchesContinueOnlyUnfinishedQueriesAndRefreshChangedOrMissingDetails()
    {
        var batches = 0;
        var lookups = new List<string>();
        var old = DateTime.Parse("2026-09-23T00:00:00Z", CultureInfo.InvariantCulture).ToUniversalTime();
        var current = old.AddDays(1);
        using var http = new HttpClient(new CallbackHandler(async request =>
        {
            if (request.Method == HttpMethod.Get)
            {
                var id = request.RequestUri!.Segments.Last();
                lookups.Add(id);
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(new
                {
                    id, modified = current, aliases = new[] { "CVE-test" }, summary = "Updated full advisory",
                    affected = new[] { new { package = new { ecosystem = "npm", name = "sample" }, versions = new[] { "1.0.0", "3.0.0" } } }
                })) };
            }
            batches++;
            using var document = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var queries = document.RootElement.GetProperty("queries");
            if (batches == 1)
            {
                Assert.AreEqual(3, queries.GetArrayLength());
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""
                    {"results":[
                      {"vulns":[{"id":"KNOWN","modified":"2026-09-23T00:00:00Z"}],"next_page_token":"next"},
                      {},
                      {"vulns":[{"id":"NEW","modified":"2026-09-24T00:00:00Z"}]}
                    ]}
                    """) };
            }
            Assert.AreEqual(1, queries.GetArrayLength());
            Assert.AreEqual("1.0.0", queries[0].GetProperty("version").GetString());
            Assert.AreEqual("next", queries[0].GetProperty("page_token").GetString());
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""
                {"results":[{"vulns":[{"id":"UPDATED","modified":"2026-09-24T00:00:00Z"}]}]}
                """) };
        }));
        var known = new Dictionary<(string, string), List<OsvAdvisory>>
        {
            [("npm", "sample")] = [new("KNOWN", [], "Known", "", old, false, "[]"),
                new("UPDATED", [], "Stale", "", old, false, "[]")]
        };

        var result = await new OsvClient(http).QueryVersionsAsync(
            [("npm", "sample", "1.0.0"), ("npm", "sample", "2.0.0"), ("npm", "sample", "3.0.0")], known);

        Assert.AreEqual(2, batches);
        CollectionAssert.AreEquivalent(new[] { "UPDATED", "NEW" }, lookups);
        Assert.HasCount(2, result[("npm", "sample", "1.0.0")]);
        Assert.IsEmpty(result[("npm", "sample", "2.0.0")]);
        Assert.AreEqual("Updated full advisory", result[("npm", "sample", "3.0.0")].Single().Summary);
        Assert.AreEqual(current, result[("npm", "sample", "1.0.0")].Single(a => a.Id == "UPDATED").ModifiedAtUtc);
        StringAssert.Contains(result[("npm", "sample", "3.0.0")].Single().AffectedJson, "3.0.0");
    }

    [TestMethod]
    [DataRow("{}")]
    [DataRow("{\"results\":[]}")]
    [DataRow("{\"results\":[{\"vulns\":{}}]}")]
    [DataRow("{\"results\":[{\"vulns\":[{\"id\":\"\",\"modified\":\"2026-09-23T00:00:00Z\"}]}]}")]
    [DataRow("{\"results\":[{\"next_page_token\":\"same\"}]}")]
    public async Task IncompleteOrMalformedVersionBatchesFailClosed(string response)
    {
        using var http = new HttpClient(new CallbackHandler(_ => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) })));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => new OsvClient(http).QueryVersionsAsync(
            [("npm", "sample", "1.0.0")], new Dictionary<(string, string), List<OsvAdvisory>>()));
    }

    [TestMethod]
    public async Task OlderAdvisoryDetailsCannotSatisfyANewerBatchRevision()
    {
        using var http = new HttpClient(new CallbackHandler(request => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(request.Method == HttpMethod.Get
                ? """{"id":"NEW","modified":"2026-09-23T00:00:00Z","affected":[]}"""
                : """{"results":[{"vulns":[{"id":"NEW","modified":"2026-09-24T00:00:00Z"}]}]}""") })));
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => new OsvClient(http).QueryVersionsAsync(
            [("npm", "sample", "1.0.0")], new Dictionary<(string, string), List<OsvAdvisory>>()));
    }

    private sealed class VersionedAdvisoryHandler : HttpMessageHandler
    {
        public bool QueriedExpectedVersion { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            using var query = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
            QueriedExpectedVersion = query.RootElement.GetProperty("version").GetString() == "4.17.20" &&
                query.RootElement.GetProperty("package").GetProperty("name").GetString() == "lodash";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                    {"vulns":[{"id":"GHSA-29mw-wpgm-hmr9","modified":"2025-09-29T21:12:31Z",
                    "aliases":["CVE-2020-28500"],
                    "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
                    "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
                    "ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]}]}
                    """)
            };
        }
    }

    private sealed class PageHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var payload = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(payload);
            var next = doc.RootElement.TryGetProperty("page_token", out _);
            var json = next
                ? """{"vulns":[{"id":"OSV-TEST-2","modified":"2026-09-23T00:00:00Z","withdrawn":"2026-09-24T00:00:00Z","affected":[]}]}"""
                : """{"vulns":[{"id":"GHSA-test-1111-2222","modified":"2026-09-23T00:00:00Z","affected":[]}],"next_page_token":"next"}""";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
        }
    }

    private sealed class RepeatHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"next_page_token":"same"}""")
            });
    }

    private sealed class WrongIdHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"id":"GHSA-other-1111-2222","modified":"2026-09-23T00:00:00Z","affected":[]}""")
            });
    }

    private sealed class CallbackHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(request);
    }
}
