namespace Aiursoft.S360.Authorization;

/// <summary>
/// Defines all permission keys as constants. This is the single source of truth.
/// </summary>
public static class AppPermissionNames
{
    public const string CanSubmitDependencyRequests = nameof(CanSubmitDependencyRequests);
    public const string CanReadSupplyChain = nameof(CanReadSupplyChain);
    public const string CanReviewDependencyRequests = nameof(CanReviewDependencyRequests);
    public const string CanManageTrustRules = nameof(CanManageTrustRules);
    public const string CanManageBlocklist = nameof(CanManageBlocklist);
    public const string CanCheckDependencies = nameof(CanCheckDependencies);
    // User Management
    public const string CanReadUsers = nameof(CanReadUsers);
    public const string CanDeleteUsers = nameof(CanDeleteUsers);
    public const string CanAddUsers = nameof(CanAddUsers);
    public const string CanEditUsers = nameof(CanEditUsers);
    public const string CanAssignRoleToUser = nameof(CanAssignRoleToUser);

    // Role Management
    public const string CanReadRoles = nameof(CanReadRoles);
    public const string CanDeleteRoles = nameof(CanDeleteRoles);
    public const string CanAddRoles = nameof(CanAddRoles);
    public const string CanEditRoles = nameof(CanEditRoles);

    // Permission Management
    public const string CanReadPermissions = nameof(CanReadPermissions);

    // System Management
    public const string CanViewSystemContext = nameof(CanViewSystemContext);
    public const string CanRebootThisApp = nameof(CanRebootThisApp);
    public const string CanViewBackgroundJobs = nameof(CanViewBackgroundJobs);
    public const string CanManageGlobalSettings = nameof(CanManageGlobalSettings);
}
