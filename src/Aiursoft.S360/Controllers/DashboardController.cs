using Aiursoft.S360.Models.DashboardViewModels;
using Aiursoft.S360.Services;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Navigation;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Controllers;

[LimitPerMin]
[Authorize]
public class DashboardController(TemplateDbContext db, UserManager<User> users,
    IAuthorizationService authorization, CatalogInventoryService inventory) : Controller
{
    [RenderInNavBar(
        NavGroupName = "Features",
        NavGroupOrder = 1,
        CascadedLinksGroupName = "Home",
        CascadedLinksIcon = "home",
        CascadedLinksOrder = 1,
        LinkText = "Overview",
        LinkOrder = 1)]
    public async Task<IActionResult> Index()
    {
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        var mine = db.DependencyApplications.AsNoTracking().Where(a => a.RequestedByUserId == userId);
        var model = new IndexViewModel
        {
            MyRequests = await mine.CountAsync(),
            MyInProgress = await mine.CountAsync(a => a.Status == ApplicationStatus.Resolving ||
                a.Status == ApplicationStatus.ReadyForReview),
            MyApproved = await mine.CountAsync(a => a.Status == ApplicationStatus.Approved),
            RecentRequests = await mine.OrderByDescending(a => a.CreatedAtUtc).Take(5).ToListAsync(),
            CanSubmitRequests = (await authorization.AuthorizeAsync(User,
                AppPermissionNames.CanSubmitDependencyRequests)).Succeeded,
            CanReadSupplyChain = (await authorization.AuthorizeAsync(User,
                AppPermissionNames.CanReadSupplyChain)).Succeeded,
            CanReviewRequests = (await authorization.AuthorizeAsync(User,
                AppPermissionNames.CanReviewDependencyRequests)).Succeeded,
            CanManageTrustRules = (await authorization.AuthorizeAsync(User,
                AppPermissionNames.CanManageTrustRules)).Succeeded,
            CanManageBlocklist = (await authorization.AuthorizeAsync(User,
                AppPermissionNames.CanManageBlocklist)).Succeeded
        };
        if (model.CanReadSupplyChain)
        {
            model.Inventory = new InventoryViewModel { Tab = "projects", CanRead = true };
            await VulnerabilityAuditSnapshot.ExecuteAsync(db, async () =>
            {
                await inventory.PopulateAsync(model.Inventory);
                return true;
            });
            model.PendingReviews = await db.DependencyApplications.CountAsync(a =>
                a.Status == ApplicationStatus.ReadyForReview);
            model.TrackedArtifacts = await db.PackageArtifacts.CountAsync();
            model.ActiveBlockRules = await db.BlockRules.CountAsync(b => b.Active);
            model.LastVulnerabilitySyncUtc = await db.VulnerabilitySyncStates.AsNoTracking()
                .Select(s => s.LastSuccessAtUtc).FirstOrDefaultAsync();
        }
        return this.StackView(model);
    }
}
