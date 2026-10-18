using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Aiursoft.S360.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Aiursoft.S360.Services.Authentication;

public class S360CheckKeyHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IConfiguration configuration) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "S360CheckKey";

    public const string BaselineClaim = "s360:baseline";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-S360-Key", out var values) ||
            values.Count != 1 || string.IsNullOrEmpty(values[0]))
            return Task.FromResult(AuthenticateResult.NoResult());

        var actual = values[0]!;
        var reviewKey = Matches(configuration["SupplyChain:CheckApiKey"], actual);
        var baselineKey = Matches(configuration["SupplyChain:BaselineApiKey"], actual);
        if (!reviewKey && !baselineKey)
            return Task.FromResult(AuthenticateResult.Fail("Invalid S360 check credential."));

        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, "s360-ci"),
                new Claim(AppPermissions.Type, AppPermissionNames.CanCheckDependencies)], SchemeName);
        // Reusing the review key must never grant production-write capability.
        if (baselineKey && !reviewKey) identity.AddClaim(new Claim(BaselineClaim, "true"));
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
    private static bool Matches(string? expected, string actual) =>
        !string.IsNullOrEmpty(expected) && CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)), SHA256.HashData(Encoding.UTF8.GetBytes(actual)));
}
