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
