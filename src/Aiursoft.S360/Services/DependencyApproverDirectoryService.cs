using Aiursoft.Scanner.Abstractions;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.FileStorage;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services;

public sealed record DependencyApproverInfo(
    string UserId,
    string DisplayName,
    string Email,
    string AvatarUrl,
    IReadOnlyList<string> RoleNames);

public class DependencyApproverDirectoryService(
    TemplateDbContext db,
    StorageService storageService) : IScopedDependency
{
    public async Task<IReadOnlyList<DependencyApproverInfo>> GetApproversAsync(
        CancellationToken cancellationToken = default)
    {
        var approverRoleIds = await db.RoleClaims.AsNoTracking()
            .Where(rc => rc.ClaimType == AppPermissions.Type &&
                         rc.ClaimValue == AppPermissionNames.CanReviewDependencyRequests)
            .Select(rc => rc.RoleId)
            .Distinct()
            .ToListAsync(cancellationToken);

        if (approverRoleIds.Count == 0)
        {
            return [];
        }

        var roleNamesById = await db.Roles.AsNoTracking()
            .Where(r => approverRoleIds.Contains(r.Id))
            .ToDictionaryAsync(r => r.Id, r => r.Name ?? string.Empty, cancellationToken);

        var userRoleMappings = await db.UserRoles.AsNoTracking()
            .Where(ur => approverRoleIds.Contains(ur.RoleId))
            .Select(ur => new { ur.UserId, ur.RoleId })
            .ToListAsync(cancellationToken);

        if (userRoleMappings.Count == 0)
        {
            return [];
        }

        var roleNamesByUserId = userRoleMappings
            .GroupBy(ur => ur.UserId)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<string>)g
                    .Select(x => roleNamesById.GetValueOrDefault(x.RoleId))
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => name!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                    .ToList());

        var userIds = roleNamesByUserId.Keys.ToList();
        var now = DateTimeOffset.UtcNow;

        var users = await db.Users.AsNoTracking()
            .Where(u => userIds.Contains(u.Id))
            .Select(u => new
            {
                u.Id,
                u.DisplayName,
                u.UserName,
                u.Email,
                u.AvatarRelativePath,
                u.LockoutEnabled,
                u.LockoutEnd
            })
            .ToListAsync(cancellationToken);

        return users
            .Where(u => !(u.LockoutEnabled && u.LockoutEnd.HasValue && u.LockoutEnd.Value > now))
            .Select(u =>
            {
                var displayName = !string.IsNullOrWhiteSpace(u.DisplayName)
                    ? u.DisplayName
                    : !string.IsNullOrWhiteSpace(u.UserName)
                        ? u.UserName
                        : u.Email ?? u.Id;
                var avatarUrl = string.IsNullOrWhiteSpace(u.AvatarRelativePath)
                    ? string.Empty
                    : $"{storageService.RelativePathToInternetUrl(u.AvatarRelativePath)}?w=72&square=true";

                return new DependencyApproverInfo(
                    u.Id,
                    displayName,
                    u.Email ?? string.Empty,
                    avatarUrl,
                    roleNamesByUserId.GetValueOrDefault(u.Id) ?? []);
            })
            .OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(a => a.Email, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
