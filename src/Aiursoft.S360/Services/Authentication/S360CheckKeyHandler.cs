using EFCoreSecondLevelCacheInterceptor;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Aiursoft.S360.Services.Authentication;

public class S360CheckKeyHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    TemplateDbContext db,
    ApiKeyPermissions permissions) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "S360CheckKey";
    public const string BaselineClaim = "s360:baseline";
    public const string KeyIdClaim = "s360:key-id";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-S360-Key", out var values) ||
            values.Count != 1 || string.IsNullOrEmpty(values[0])) return AuthenticateResult.NoResult();
        var actual = values[0]!;
        if (actual.Length > 512) return AuthenticateResult.Fail("Invalid S360 check credential.");
        var hash = ApiKeyPermissions.Hash(actual);
        var key = await db.ApiKeys.NotCacheable().SingleOrDefaultAsync(k => k.SecretHash == hash);
        if (key == null || !key.IsEnabled || key.ExpirationTime <= DateTime.UtcNow ||
            !await permissions.HasAsync(key.UserId, AppPermissionNames.CanManageApiKeys))
            return AuthenticateResult.Fail("Invalid S360 check credential.");
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, key.UserId),
                new Claim(KeyIdClaim, key.Id.ToString()),
                new Claim(AppPermissions.Type, AppPermissionNames.CanCheckDependencies)], SchemeName);
        if (key.CanPublishBaselines && await permissions.HasAsync(key.UserId, AppPermissionNames.CanPublishBaselines))
            identity.AddClaim(new Claim(BaselineClaim, "true"));
        key.LastUsed = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }
}
