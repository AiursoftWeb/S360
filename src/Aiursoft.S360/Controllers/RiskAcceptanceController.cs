using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.UiStack.Navigation;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Controllers;

[Authorize(Policy = AppPermissionNames.CanReadSupplyChain)]
[LimitPerMin]
public class RiskAcceptanceController(TemplateDbContext db, UserManager<User> users,
    IConfiguration configuration) : Controller
{
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Packages and rules", CascadedLinksIcon = "package-check", CascadedLinksOrder = 2,
        LinkText = "Risk acceptance", LinkOrder = 3)]
    public async Task<IActionResult> Index(string filter = "active", int page = 1, int? vulnerabilityId = null)
    {
        if (filter is not ("active" or "pending" or "all") || page is < 1 or > 10000) return BadRequest();
        var now = DateTime.UtcNow;
        var query = db.Rules.AsNoTracking().Where(r => r.Kind == RuleKind.RiskAcceptance);
        query = filter switch
        {
            "active" => query.Where(r => r.Status == RuleStatus.Approved && r.ExpiresAtUtc > now),
            "pending" => query.Where(r => r.Status == RuleStatus.Pending),
            _ => query
        };
        var total = await query.CountAsync();
        page = Math.Min(page, Math.Max(1, (total + 49) / 50));
        var model = new RiskAcceptanceViewModel
        {
            Filter = filter, Page = page, Total = total,
            Rules = await query.Include(r => r.Vulnerability).Include(r => r.Reviews)
                .OrderByDescending(r => r.Id).Skip((page - 1) * 50).Take(50).ToListAsync()
        };
        if (vulnerabilityId != null)
        {
            model.Advisory = await db.Vulnerabilities.AsNoTracking().FirstOrDefaultAsync(v => v.Id == vulnerabilityId);
            if (model.Advisory == null) return NotFound();
            var setting = model.Advisory.Ecosystem == "npm" ? "SupplyChain:NpmSources" : "SupplyChain:NuGetSources";
            model.Sources = (configuration.GetSection(setting).Get<string[]>() ?? [])
                .Select(TrustPattern.NormalizeSource).Distinct().ToList();
        }
        var ids = model.Rules.Select(r => r.RequestedByUserId)
            .Concat(model.Rules.SelectMany(r => r.Reviews).Select(r => r.ReviewerId)).Distinct().ToList();
        model.UserNames = await db.Users.Where(u => ids.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.DisplayName == "" ? u.UserName ?? u.Id : u.DisplayName);
        return this.StackView(model);
    }

    [HttpPost, ValidateAntiForgeryToken]
    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    public Task<IActionResult> Submit(int vulnerabilityId, string version, string source, DateTime expiresAtUtc, string reason)
        => VulnerabilityAuditSnapshot.ExecuteAsync<IActionResult>(db, async () =>
        {
            expiresAtUtc = UtcExpiry.Normalize(expiresAtUtc);
            var now = DateTime.UtcNow;
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(reason) || reason.Length > 2000 ||
                !TrustPattern.IsValidVersionPattern(version) || expiresAtUtc <= now || expiresAtUtc > now.AddYears(2))
                return BadRequest();
            try { source = TrustPattern.NormalizeSource(source); }
            catch (ArgumentException) { return BadRequest("Invalid package source."); }
            var advisory = await db.Vulnerabilities.FindAsync(vulnerabilityId);
            if (advisory == null) return NotFound();
            if (advisory.Withdrawn || !TrustService.IsValidPackageName(advisory.Ecosystem, advisory.PackageName) ||
                !AllowedPackageSources.Contains(configuration, advisory.Ecosystem, source) ||
                OsvRangeMatcher.Intersects(advisory.RawAffectedJson, advisory.Ecosystem, advisory.PackageName,
                    version) != RangeRisk.Affected)
                return BadRequest("The selected version scope must have a confirmed active finding.");
            var user = users.GetUserId(User);
            if (user == null) return Unauthorized();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Pending,
                VulnerabilityId = advisory.Id, Ecosystem = advisory.Ecosystem, PackagePattern = advisory.PackageName,
                Version = version, Source = source, Justification = reason.Trim(),
                RequestedByUserId = user, ExpiresAtUtc = expiresAtUtc
            });
            await db.SaveChangesAsync();
            return RedirectToAction(nameof(Index), new { filter = "pending" });
        });

    [HttpPost, ValidateAntiForgeryToken]
    [Authorize(Policy = AppPermissionNames.CanManageVulnerabilityExceptions)]
    public Task<IActionResult> Approve(int id, string reason) => Decide(id, RuleStatus.Approved, reason);

    [HttpPost, ValidateAntiForgeryToken]
    [Authorize(Policy = AppPermissionNames.CanManageVulnerabilityExceptions)]
    public Task<IActionResult> Reject(int id, string reason) => Decide(id, RuleStatus.Rejected, reason);

    [HttpPost, ValidateAntiForgeryToken]
    [Authorize(Policy = AppPermissionNames.CanManageVulnerabilityExceptions)]
    public Task<IActionResult> Revoke(int id, string reason) => Decide(id, RuleStatus.Revoked, reason);

    private Task<IActionResult> Decide(int id, RuleStatus decision, string reason) =>
        VulnerabilityAuditSnapshot.ExecuteAsync<IActionResult>(db, async () =>
        {
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) return BadRequest();
            var rule = await db.Rules.Include(r => r.Vulnerability)
                .SingleOrDefaultAsync(r => r.Id == id && r.Kind == RuleKind.RiskAcceptance);
            if (rule == null) return NotFound();
            var user = users.GetUserId(User);
            if (user == null) return Unauthorized();
            var now = DateTime.UtcNow;
            if (decision == RuleStatus.Revoked ? rule.Status != RuleStatus.Approved : rule.Status != RuleStatus.Pending)
                return BadRequest("This decision is no longer available. Reload the review.");
            if (decision == RuleStatus.Approved && (rule.ExpiresAtUtc == null || rule.ExpiresAtUtc <= now ||
                rule.Vulnerability is not { Withdrawn: false } ||
                !AllowedPackageSources.Contains(configuration, rule.Ecosystem, rule.Source)))
                return BadRequest("The risk acceptance scope is expired or no longer applicable.");
            rule.Status = decision;
            db.RuleChanges.Add(new RuleChange
            {
                Rule = rule, Decision = decision, ReviewerId = user, Reason = reason.Trim(),
                ReviewedAtUtc = now, ExpiresAtUtc = rule.ExpiresAtUtc
            });
            await db.SaveChangesAsync();
            return RedirectToAction(nameof(Index), new { filter = "all" });
        });
}
