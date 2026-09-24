using Aiursoft.AiurProtocol;
using Aiursoft.AiurProtocol.Services;

namespace Aiursoft.S360.SDK;

public class S360Client(AiurProtocolClient client)
{
    public Task<CheckResponse> CheckAsync(string server, string apiKey, CheckRequest request)
    {
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("S360 server must use HTTPS (HTTP is allowed for local development only).");
        }
        return client.Post<CheckResponse>(
            new AiurApiEndpoint(server.TrimEnd('/'), "/api/check", new { }),
            new AiurApiPayload(request),
            format: BodyFormat.HttpJsonBody,
            autoRetry: false,
            headers: new Dictionary<string, string> { ["X-S360-Key"] = apiKey });
    }
}
