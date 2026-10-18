using EFCoreSecondLevelCacheInterceptor;
using System.Security.Cryptography;
using System.Text;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services.Authentication;

public class ApiKeyPermissions(TemplateDbContext db) : IScopedDependency
{
    public static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    // Read current grants, not the browser cookie, so revocation also revokes issued keys.
    public async Task<bool> HasAsync(string userId, string permission)
    {
        var user = await db.Users.NotCacheable().AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId);
        if (user == null || user.LockoutEnabled && user.LockoutEnd > DateTimeOffset.UtcNow) return false;
        return await db.UserClaims.NotCacheable().AnyAsync(c => c.UserId == userId &&
                c.ClaimType == AppPermissions.Type && c.ClaimValue == permission) ||
            await (from membership in db.UserRoles.NotCacheable()
                join claim in db.RoleClaims on membership.RoleId equals claim.RoleId
                where membership.UserId == userId && claim.ClaimType == AppPermissions.Type &&
                    claim.ClaimValue == permission
                select claim.Id).AnyAsync();
    }
}
