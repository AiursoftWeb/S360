using Aiursoft.AiurProtocol;
using Aiursoft.AiurProtocol.Services;
using Aiursoft.AiurProtocol.Exceptions;
using System.Net;

namespace Aiursoft.S360.SDK;

public class S360Client(AiurProtocolClient client)
{
    public bool SupportsSolutionGraphs { get; private set; }
    /// <summary>Wait only for vulnerability data for policy-approved review dependencies.</summary>
    public async Task<CheckResponse> CheckWhenReadyAsync(string server, string? apiKey, CheckRequest request,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        if (request.Context?.Purpose is not (null or "review"))
            throw new ArgumentException("Only reviews may be polled; baseline batches must be submitted once.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            while (true)
            {
                CheckResponse response;
                try
                {
                    response = await CheckAsync(server, apiKey, request).WaitAsync(deadline.Token);
                }
                catch (AiurHttpResponseException ex) when (ex.StatusCode == HttpStatusCode.TooManyRequests)
                {
                    // Only the preflight review is retried. A baseline submission
                    // must remain a single request, even after a transport error.
                    var delay = ex.RetryAfter ?? TimeSpan.FromMinutes(1);
                    if (delay < TimeSpan.FromSeconds(1)) delay = TimeSpan.FromSeconds(1);
                    Console.WriteLine("S360 review is rate limited; waiting before retrying within the verification deadline.");
                    // A Retry-After beyond the entire budget must end at the
                    // deadline, never race it into another request.
                    if (delay >= timeout)
                        await Task.Delay(Timeout.InfiniteTimeSpan, deadline.Token);
                    else
                        await Task.Delay(delay + TimeSpan.FromMilliseconds(Random.Shared.Next(100, 1000)), deadline.Token);
                    continue;
                }
                var denied = response.Decisions.Where(d => !d.Trusted).ToList();
                if (response.Trusted || denied.Count == 0 || denied.Any(d => !d.PendingVerification))
                    return response;
                Console.WriteLine($"S360 is refreshing vulnerability data for {denied.Count} approved package versions; waiting.");
                await Task.Delay(TimeSpan.FromSeconds(15), deadline.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("S360 vulnerability refresh did not complete within the wait limit. " +
                "The build remains blocked; check vulnerability audit job results, then retry.");
        }
    }

    public async Task<CheckResponse> CheckAsync(string server, string? apiKey, CheckRequest request)
    {
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("S360 server must use HTTPS (HTTP is allowed for local development only).");
        }
        var headers = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(apiKey)) headers["X-S360-Key"] = apiKey;
        var response = await client.Post<CheckResponse>(
            new AiurApiEndpoint(server.TrimEnd('/'), "/api/check", new { }),
            new AiurApiPayload(request),
            format: BodyFormat.HttpJsonBody,
            autoRetry: false,
            headers: headers);
        if (request.SolutionGraph != null)
        {
            if (response.SolutionGraphVersion != 1)
                throw new InvalidOperationException("The S360 server does not support solution reports yet. Deploy the server update before using this CLI.");
            SupportsSolutionGraphs = true;
        }
        if (response.Code != AiurProtocol.Models.Code.ResultShown ||
            response.Decisions.Count != request.Dependencies.Count)
            throw new InvalidOperationException("S360 returned an incomplete dependency decision set.");
        for (var i = 0; i < request.Dependencies.Count; i++)
        {
            var expected = request.Dependencies[i];
            var actual = response.Decisions[i].Dependency;
            if (actual.Ecosystem != expected.Ecosystem || actual.Name != expected.Name ||
                actual.Version != expected.Version || actual.Source != expected.Source ||
                !actual.Sha256.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("S360 returned a mismatched dependency decision set.");
        }
        return response;
    }
}
