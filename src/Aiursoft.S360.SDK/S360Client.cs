using Aiursoft.AiurProtocol;
using Aiursoft.AiurProtocol.Services;

namespace Aiursoft.S360.SDK;

public class S360Client(AiurProtocolClient client)
{
    /// <summary>Wait only for independent verification of policy-approved review dependencies.</summary>
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
                var response = await CheckAsync(server, apiKey, request).WaitAsync(deadline.Token);
                var denied = response.Decisions.Where(d => !d.Trusted).ToList();
                if (response.Trusted || denied.Count == 0 || denied.Any(d => !d.PendingVerification))
                    return response;
                Console.WriteLine($"S360 is independently verifying and auditing {denied.Count} approved package versions; waiting.");
                await Task.Delay(TimeSpan.FromSeconds(15), deadline.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("S360 package verification did not complete within the wait limit. " +
                "The build remains blocked; check source verification and vulnerability audit job results, then retry.");
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
        if (response.Code != Aiursoft.AiurProtocol.Models.Code.ResultShown ||
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
