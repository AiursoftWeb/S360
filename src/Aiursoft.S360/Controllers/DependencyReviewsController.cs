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
public class DependencyReviewsController(TemplateDbContext db, UserManager<User> users, TrustService trust,
    IConfiguration configuration) : Controller
{
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Requests", CascadedLinksIcon = "inbox", CascadedLinksOrder = 3,
        LinkText = "Approvals", LinkOrder = 3)]
    public async Task<IActionResult> Index(string filter = "pending", int page = 1)
        => await VulnerabilityAuditSnapshot.ReadAsync(db, () => IndexSnapshotAsync(filter, page));

    private async Task<IActionResult> IndexSnapshotAsync(string filter, int page)
    {
        if (filter is not ("pending" or "expiring" or "expired" or "all") || page is < 1 or > 10000)
            return BadRequest();
        var now = DateTime.UtcNow;
        var threshold = now.AddDays(30);
        var applications = db.DependencyApplications.AsNoTracking();
        var pending = applications.Where(a => a.Status == ApplicationStatus.ReadyForReview);
        var expiring = applications.Where(a => a.Status == ApplicationStatus.Approved &&
            db.Rules.Where(r => r.Kind == RuleKind.Approval).Any(r => r.ApplicationId == a.Id && r.Status == RuleStatus.Approved &&
                r.ExpiresAtUtc > now && r.ExpiresAtUtc <= threshold));
        var expired = applications.Where(a => a.Status == ApplicationStatus.Approved &&
            db.Rules.Where(r => r.Kind == RuleKind.Approval).Any(r => r.ApplicationId == a.Id && r.Status == RuleStatus.Approved &&
                r.ExpiresAtUtc <= now));
        var filtered = filter switch
        {
            "pending" => pending,
            "expiring" => expiring,
            "expired" => expired,
            _ => applications.Where(a => a.Status == ApplicationStatus.ReadyForReview ||
                a.Status == ApplicationStatus.Approved || a.Status == ApplicationStatus.Revoked)
        };
        var total = await filtered.CountAsync();
        page = Math.Min(page, Math.Max(1, (total + 49) / 50));
        var model = new ReviewApplicationsViewModel
        {
            Filter = filter,
            Page = page,
            PendingCount = await pending.CountAsync(),
            ExpiringCount = await expiring.CountAsync(),
            ExpiredCount = await expired.CountAsync(),
            Total = total,
            Applications = await filtered.OrderByDescending(a => a.CreatedAtUtc).ThenByDescending(a => a.Id)
                .Skip((page - 1) * 50).Take(50).ToListAsync()
        };
        model.ApplicationsWithRemovedSources = model.Applications
            .Where(application => !AllowedPackageSources.Contains(configuration,
                application.Ecosystem, application.Source))
            .Select(application => application.Id).ToHashSet();
        var visibleIds = model.Applications.Select(a => a.Id).ToList();
        if (visibleIds.Count > 0)
        {
            var reportPackages = await db.ApplicationPackages.AsNoTracking()
                .Include(p => p.PackageVersion)
                .Where(p => visibleIds.Contains(p.ApplicationId))
                .ToListAsync();
            foreach (var application in model.Applications)
            {
                var current = new DependencyApplication
                {
                    Ecosystem = application.Ecosystem,
                    Source = application.Source,
                    DirectPackages = application.DirectPackages,
                    ResolutionContext = application.ResolutionContext,
                    Packages = reportPackages.Where(p => p.ApplicationId == application.Id).ToList()
                };
                try { application.ReportHash = ReportFingerprint.ComputePersisted(current); }
                catch (InvalidOperationException) { application.ReportHash = null; }
            }
            var artifacts = reportPackages
                .Select(p => p.PackageVersion).DistinctBy(a => a.Id).ToList();
            var dependencies = artifacts.Select(a => new Dependency
            {
                Ecosystem = a.Ecosystem,
                Name = a.Name,
                Version = a.Version,
                Source = a.Source
            }).ToList();
            var assessment = await trust.AssessForDisplayAsync(dependencies);
            var sourcePermitted = artifacts.ToDictionary(a => a.Id, a =>
                AllowedPackageSources.Contains(configuration, a.Ecosystem, a.Source));
            var authorized = artifacts.Zip(assessment.Authorization).ToDictionary(pair => pair.First.Id,
                pair => sourcePermitted[pair.First.Id] && pair.Second.Trusted);
            var cleared = artifacts.Zip(assessment.Decisions).ToDictionary(pair => pair.First.Id,
                pair => sourcePermitted[pair.First.Id] && pair.Second.Trusted);
            var audit = assessment.Audit;
            var blockingIds = artifacts.Zip(assessment.Vulnerabilities).Where(pair => pair.Second.Blocking.Count > 0)
                .Select(pair => pair.First.Id).ToHashSet();
            foreach (var group in reportPackages.GroupBy(p => p.ApplicationId))
            {
                var entries = group.ToList();
                model.PackagesByApplicationId[group.Key] = entries
                    .OrderByDescending(p => p.IsDirect).ThenBy(p => p.PackageVersion.Name, StringComparer.Ordinal)
                    .Select(p => new ReviewPackageLine(p.PackageVersion, p.IsDirect,
                        authorized.GetValueOrDefault(p.PackageVersionId),
                        sourcePermitted.GetValueOrDefault(p.PackageVersionId),
                        VulnerabilityAuditFreshness.IsCurrent(p.PackageVersion.LastCheckedAtUtc,
                            audit?.LastSuccessfulAttemptAtUtc, audit?.LastSuccessAtUtc, now),
                        blockingIds.Contains(p.PackageVersionId), cleared.GetValueOrDefault(p.PackageVersionId)))
                    .ToList();
            }
        }
        return this.StackView(model);
    }

    [Authorize(Policy = AppPermissionNames.CanReviewDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Approve(int id, string reportHash,
        DateTime expiresAtUtc, string reason)
        => await VulnerabilityAuditSnapshot.ExecuteAsync(db, () => ApproveSnapshotAsync(id, reportHash, expiresAtUtc, reason));

    private async Task<IActionResult> ApproveSnapshotAsync(int id, string reportHash,
        DateTime expiresAtUtc, string reason)
    {
        expiresAtUtc = UtcExpiry.Normalize(expiresAtUtc);
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000 ||
            expiresAtUtc <= DateTime.UtcNow || expiresAtUtc > DateTime.UtcNow.AddYears(2)) return BadRequest();
        var application = await db.DependencyApplications.Include(a => a.Packages)
            .ThenInclude(p => p.PackageVersion).FirstOrDefaultAsync(a => a.Id == id);
        if (application == null) return NotFound();
        if (application.Status is not (ApplicationStatus.ReadyForReview or ApplicationStatus.Approved or ApplicationStatus.Revoked) ||
            application.Packages.Count() == 0) return BadRequest("The review report is unavailable or has changed.");
        if (!AllowedPackageSources.Contains(configuration, application.Ecosystem, application.Source))
            return BadRequest("The package source is no longer permitted for approval.");
        try
        {
            if (ReportFingerprint.ComputePersisted(application) != reportHash)
                return BadRequest("The saved dependency report no longer matches its fingerprint.");
        }
        catch (InvalidOperationException)
        {
            return BadRequest("The saved dependency report is incomplete or inconsistent.");
        }
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        if (userId == application.RequestedByUserId) return BadRequest("Applicants cannot approve their own requests.");

        var now = DateTime.UtcNow;
        var audit = await db.VulnerabilitySyncStates.AsNoTracking()
            .Select(s => new { s.LastSuccessfulAttemptAtUtc, s.LastSuccessAtUtc }).FirstOrDefaultAsync();
        var blocks = await db.Rules.Where(r => r.Kind == RuleKind.Block).AsNoTracking().Where(b => b.Status == RuleStatus.Approved && b.Ecosystem == application.Ecosystem).ToListAsync();
        var rules = await db.Rules.Where(r => r.Kind == RuleKind.Approval).Where(r => r.Ecosystem == application.Ecosystem).ToListAsync();
        var exclusions = await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var packages = application.Packages.Select(entry => entry.PackageVersion).Select(artifact => (artifact,
            dependency: new Dependency
            {
                Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version, Source = artifact.Source
            })).ToList();
        var vulnerabilities = await VulnerabilityPolicy.LoadAsync(db, now, packages.Select(p => p.dependency).ToList());

        foreach (var (artifact, dependency) in packages)
        {
            var block = BlockRulePolicy.Match(blocks, artifact.Ecosystem, artifact.Name, artifact.Version);
            if (block != null)
                return BadRequest(BlockRulePolicy.Explain(block, artifact.Name, artifact.Version,
                    artifact.Name));
            // An exact batch approval must not override an exclusion on an existing rule.
            var excluded = rules.Where(r => r.Status == RuleStatus.Approved &&
                    (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
                    r.Source == artifact.Source &&
                    r.MatchesPackage(artifact.Name) &&
                    TrustPattern.VersionMatches(r.Version, artifact.Version, artifact.Ecosystem, r.IncludePrerelease))
                .Select(r => TrustService.MatchingExclusion(r, dependency, exclusions))
                .FirstOrDefault(e => e != null);
            if (excluded != null)
                return BadRequest($"Excluded version: {artifact.Name}@{artifact.Version} " +
                    $"({excluded.Vulnerability!.SourceId}). {excluded.Justification} " +
                    $"Introduction path: {artifact.Name}");
            if (!VulnerabilityAuditFreshness.IsCurrent(artifact.LastCheckedAtUtc,
                    audit?.LastSuccessfulAttemptAtUtc, audit?.LastSuccessAtUtc, now))
                return BadRequest($"Vulnerability audit is missing or stale: {artifact.Name}@{artifact.Version}.");
            if (vulnerabilities.Assess(dependency).Blocking.Count > 0)
                return BadRequest($"Known active vulnerability: {artifact.Name}@{artifact.Version}.");
            if (rules.Any(r => r.ApplicationId != application.Id &&
                r.Status is RuleStatus.Rejected or RuleStatus.Revoked &&
                r.Source == artifact.Source &&
                r.MatchesPackage(artifact.Name) &&
                TrustPattern.VersionMatches(r.Version, artifact.Version, artifact.Ecosystem, r.IncludePrerelease)))
                return BadRequest($"A separate rejection/revocation blocks {artifact.Name}@{artifact.Version}.");

        }

        var decisionBatchId = Guid.NewGuid().ToString("N");
        foreach (var entry in application.Packages)
        {
            var artifact = entry.PackageVersion;
            var existing = rules.FirstOrDefault(r => r.ApplicationId == application.Id &&
                r.PackagePattern.Equals(artifact.Name, artifact.Ecosystem == "nuget" ?
                    StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                r.Version == artifact.Version && r.Source == artifact.Source);
            if (existing == null)
            {
                existing = new PackageRule
                {
                    ApplicationId = application.Id,
                    Ecosystem = artifact.Ecosystem,
                    PackagePattern = artifact.Name,
                    Version = artifact.Version,
                    Source = artifact.Source,
                    RequestedByUserId = application.RequestedByUserId,
                    Justification = application.Justification,
                    Status = RuleStatus.Approved,
                    ExpiresAtUtc = expiresAtUtc
                };
                db.Rules.Add(existing);
            }
            else
            {
                existing.Status = RuleStatus.Approved;
                existing.ExpiresAtUtc = expiresAtUtc;
            }
            db.RuleChanges.Add(new RuleChange
            {
                RuleId = existing.Id,
                Rule = existing,
                Decision = RuleStatus.Approved,
                ReviewerId = userId,
                Reason = reason,
                ExpiresAtUtc = expiresAtUtc,
                ReportHash = reportHash,
                DecisionBatchId = decisionBatchId,
                ReviewedAtUtc = now
            });
        }
        application.Status = ApplicationStatus.Approved;
        application.DecidedByUserId = userId;
        application.DecidedAtUtc = now;
        application.DecisionReason = reason;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Policy = AppPermissionNames.CanReviewDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Reject(int id, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) return BadRequest();
        var application = await db.DependencyApplications.FindAsync(id);
        if (application == null) return NotFound();
        if (application.Status != ApplicationStatus.ReadyForReview) return BadRequest();
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        application.Status = ApplicationStatus.Rejected;
        application.DecidedByUserId = userId;
        application.DecidedAtUtc = DateTime.UtcNow;
        application.DecisionReason = reason;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    [Authorize(Policy = AppPermissionNames.CanReviewDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Revoke(int id, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) return BadRequest();
        var application = await db.DependencyApplications.FindAsync(id);
        if (application == null) return NotFound();
        if (application.Status != ApplicationStatus.Approved) return BadRequest();
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        var decisionBatchId = Guid.NewGuid().ToString("N");
        var decidedAtUtc = DateTime.UtcNow;
        var rules = await db.Rules.Where(r => r.Kind == RuleKind.Approval).Where(r => r.ApplicationId == id && r.Status == RuleStatus.Approved).ToListAsync();
        foreach (var rule in rules)
        {
            rule.Status = RuleStatus.Revoked;
            db.RuleChanges.Add(new RuleChange
            {
                RuleId = rule.Id,
                Decision = RuleStatus.Revoked,
                ReviewerId = userId,
                Reason = reason,
                ReportHash = application.ReportHash,
                DecisionBatchId = decisionBatchId,
                ReviewedAtUtc = decidedAtUtc
            });
        }
        application.Status = ApplicationStatus.Revoked;
        application.DecidedByUserId = userId;
        application.DecidedAtUtc = decidedAtUtc;
        application.DecisionReason = reason;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }
}
