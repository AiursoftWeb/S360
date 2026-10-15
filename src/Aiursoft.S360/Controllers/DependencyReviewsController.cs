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
    [RenderInNavBar(NavGroupName = "Administration", NavGroupOrder = 9998,
        CascadedLinksGroupName = "Supply chain", CascadedLinksIcon = "clipboard-check", CascadedLinksOrder = 10,
        LinkText = "Dependency approvals", LinkOrder = 2)]
    public async Task<IActionResult> Index(string filter = "pending", int page = 1)
    {
        if (filter is not ("pending" or "expiring" or "expired" or "all") || page is < 1 or > 10000)
            return BadRequest();
        var now = DateTime.UtcNow;
        var threshold = now.AddDays(30);
        var applications = db.DependencyApplications.AsNoTracking();
        var pending = applications.Where(a => a.Status == ApplicationStatus.ReadyForReview);
        var expiring = applications.Where(a => a.Status == ApplicationStatus.Approved &&
            db.TrustRules.Any(r => r.ApplicationId == a.Id && r.Status == TrustRuleStatus.Approved &&
                r.ExpiresAtUtc > now && r.ExpiresAtUtc <= threshold));
        var expired = applications.Where(a => a.Status == ApplicationStatus.Approved &&
            db.TrustRules.Any(r => r.ApplicationId == a.Id && r.Status == TrustRuleStatus.Approved &&
                r.ExpiresAtUtc <= now));
        var filtered = filter switch
        {
            "pending" => pending,
            "expiring" => expiring,
            "expired" => expired,
            _ => applications.Where(a => a.Status == ApplicationStatus.ReadyForReview ||
                a.Status == ApplicationStatus.Approved || a.Status == ApplicationStatus.Revoked)
        };
        var model = new ReviewApplicationsViewModel
        {
            Filter = filter, Page = page,
            PendingCount = await pending.CountAsync(),
            ExpiringCount = await expiring.CountAsync(),
            ExpiredCount = await expired.CountAsync(),
            Total = await filtered.CountAsync(),
            Applications = await filtered.OrderByDescending(a => a.CreatedAtUtc)
                .Skip((page - 1) * 50).Take(50).ToListAsync(),
            Suppliers = await db.Suppliers.AsNoTracking().OrderBy(s => s.Name).ToListAsync()
        };
        model.ApplicationsWithRemovedSources = model.Applications
            .Where(application => !AllowedPackageSources.Contains(configuration,
                application.Ecosystem, application.Source))
            .Select(application => application.Id).ToHashSet();
        var visibleIds = model.Applications.Select(a => a.Id).ToList();
        if (visibleIds.Count > 0)
        {
            var reportPackages = await db.ApplicationPackages.AsNoTracking()
                .Include(p => p.PackageArtifact)
                .Where(p => visibleIds.Contains(p.ApplicationId))
                .ToListAsync();
            var artifacts = reportPackages
                .Select(p => p.PackageArtifact).DistinctBy(a => a.Id).ToList();
            var decisions = await trust.AssessAsync(artifacts.Select(a => new Dependency
            {
                Ecosystem = a.Ecosystem, Name = a.Name, Version = a.Version,
                Source = a.Source, Sha256 = a.Sha256
            }));
            var currentRules = await db.TrustRules.AsNoTracking()
                .Where(r => r.Status != TrustRuleStatus.Pending).ToListAsync();
            var currentBlocks = await db.BlockRules.AsNoTracking().Where(b => b.Active).ToListAsync();
            var currentExclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking()
                .Include(e => e.Vulnerability).ToListAsync();
            var sourcePermitted = artifacts.ToDictionary(a => a.Id, a =>
                AllowedPackageSources.Contains(configuration, a.Ecosystem, a.Source));
            var authorized = artifacts.ToDictionary(a => a.Id, a =>
                sourcePermitted[a.Id] &&
                TrustService.Evaluate(new Dependency
            {
                Ecosystem = a.Ecosystem, Name = a.Name, Version = a.Version,
                Source = a.Source, Sha256 = a.Sha256
            }, currentRules, currentBlocks, now, currentExclusions).Trusted);
            var cleared = artifacts.Zip(decisions).ToDictionary(pair => pair.First.Id,
                pair => sourcePermitted[pair.First.Id] && pair.Second.Trusted);
            foreach (var group in reportPackages.GroupBy(p => p.ApplicationId))
            {
                var entries = group.ToList();
                var sourceRemoved = entries.Count(p => !sourcePermitted.GetValueOrDefault(p.PackageArtifactId));
                var needingReview = entries.Where(p => sourcePermitted.GetValueOrDefault(p.PackageArtifactId) &&
                        !authorized.GetValueOrDefault(p.PackageArtifactId))
                    .Select(p => $"{p.PackageArtifact.Name}@{p.PackageArtifact.Version}")
                    .OrderBy(name => name, StringComparer.Ordinal).ToList();
                var onHold = entries.Where(p => authorized.GetValueOrDefault(p.PackageArtifactId) &&
                        !cleared.GetValueOrDefault(p.PackageArtifactId))
                    .Select(p => $"{p.PackageArtifact.Name}@{p.PackageArtifact.Version}")
                    .OrderBy(name => name, StringComparer.Ordinal).ToList();
                model.ScopeByApplicationId[group.Key] = new ReviewApplicationScope(entries.Count,
                    entries.Count - needingReview.Count - sourceRemoved,
                    entries.Count - needingReview.Count - sourceRemoved - onHold.Count, sourceRemoved,
                    needingReview.Take(5).ToList(), onHold.Take(5).ToList());
            }
        }
        return this.StackView(model);
    }

    [Authorize(Policy = AppPermissionNames.CanReviewDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Approve(int id, string reportHash, int supplierId,
        DateTime expiresAtUtc, string reason)
    {
        expiresAtUtc = UtcExpiry.Normalize(expiresAtUtc);
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000 ||
            expiresAtUtc <= DateTime.UtcNow || expiresAtUtc > DateTime.UtcNow.AddYears(2)) return BadRequest();
        var application = await db.DependencyApplications.Include(a => a.Packages)
            .ThenInclude(p => p.PackageArtifact).Include(a => a.Edges).FirstOrDefaultAsync(a => a.Id == id);
        if (application == null) return NotFound();
        if (application.Status is not (ApplicationStatus.ReadyForReview or ApplicationStatus.Approved or ApplicationStatus.Revoked) ||
            application.ReportHash == null || application.ReportHash != reportHash ||
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
        if (!await db.Suppliers.AnyAsync(s => s.Id == supplierId)) return BadRequest("Select an existing supplier.");

        var now = DateTime.UtcNow;
        var audit = await db.VulnerabilitySyncStates.AsNoTracking()
            .Select(s => new { s.LastAttemptAtUtc, s.LastSuccessAtUtc, s.LastError }).FirstOrDefaultAsync();
        if (VulnerabilityAuditFreshness.HasFailedLatestAttempt(audit?.LastAttemptAtUtc,
                audit?.LastSuccessAtUtc, audit?.LastError))
            return BadRequest("The latest vulnerability audit failed; retry it before approving dependencies.");
        var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active && b.Ecosystem == application.Ecosystem).ToListAsync();
        var rules = await db.TrustRules.Where(r => r.Ecosystem == application.Ecosystem).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var affectedIds = (await db.VulnerabilityMatches.AsNoTracking()
            .Where(m => m.Active && !m.Vulnerability.Withdrawn)
            .Select(m => m.PackageArtifactId).ToListAsync()).ToHashSet();
        var sameIdentity = await db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == application.Ecosystem)
            .ToListAsync();
        var artifacts = application.Packages.ToDictionary(p => p.PackageArtifactId, p => p.PackageArtifact);
        var paths = ApplicationPaths.Build(application.Edges, artifacts);

        foreach (var entry in application.Packages)
        {
            var artifact = entry.PackageArtifact;
            var block = BlockRulePolicy.Match(blocks, artifact.Ecosystem, artifact.Name, artifact.Version);
            if (block != null)
                return BadRequest(BlockRulePolicy.Explain(block, artifact.Name, artifact.Version,
                    paths.GetValueOrDefault(artifact.Id, artifact.Name)));
            var dependency = new Dependency
            {
                Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
                Source = artifact.Source, Sha256 = artifact.Sha256
            };
            // An exact batch approval must not override an exclusion on an existing rule.
            var excluded = rules.Where(r => r.Status == TrustRuleStatus.Approved &&
                    (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
                    r.Source == artifact.Source &&
                    TrustPattern.Matches(r.PackagePattern, artifact.Name, artifact.Ecosystem) &&
                    TrustPattern.VersionMatches(r.Version, artifact.Version, artifact.Ecosystem, r.IncludePrerelease))
                .Select(r => TrustService.MatchingExclusion(r, dependency, exclusions))
                .FirstOrDefault(e => e != null);
            if (excluded != null)
                return BadRequest($"Excluded version: {artifact.Name}@{artifact.Version} " +
                    $"({excluded.Vulnerability.SourceId}). {excluded.Reason} " +
                    $"Introduction path: {paths.GetValueOrDefault(artifact.Id, artifact.Name)}");
            if (artifact.SourceVerifiedAtUtc == null)
                return BadRequest($"Package archive has not been independently verified from its source: {artifact.Name}@{artifact.Version}.");
            if (!VulnerabilityAuditFreshness.IsCurrent(artifact.LastCheckedAtUtc,
                    audit?.LastAttemptAtUtc, audit?.LastSuccessAtUtc, now))
                return BadRequest($"Vulnerability audit is missing or stale: {artifact.Name}@{artifact.Version}.");
            if (affectedIds.Contains(artifact.Id))
                return BadRequest($"Known active vulnerability: {artifact.Name}@{artifact.Version}.");
            if (sameIdentity.Any(a => a.Id != artifact.Id &&
                (a.SourceVerifiedAtUtc != null || a.FirstTrustedAtUtc != null) &&
                a.Name.Equals(artifact.Name, artifact.Ecosystem == "nuget" ?
                    StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                a.Version == artifact.Version && a.Source == artifact.Source &&
                !a.Sha256.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase)))
                return BadRequest($"Previously verified package bytes differ: {artifact.Name}@{artifact.Version}.");
            if (rules.Any(r => r.ApplicationId != application.Id &&
                r.Status is TrustRuleStatus.Rejected or TrustRuleStatus.Revoked &&
                r.Source == artifact.Source &&
                TrustPattern.Matches(r.PackagePattern, artifact.Name, artifact.Ecosystem) &&
                TrustPattern.VersionMatches(r.Version, artifact.Version, artifact.Ecosystem, r.IncludePrerelease)))
                return BadRequest($"A separate rejection/revocation blocks {artifact.Name}@{artifact.Version}.");
            if (rules.Any(r => r.ApplicationId != application.Id && r.Status == TrustRuleStatus.Approved &&
                r.Sha256 != null && r.Source == artifact.Source && r.Version == artifact.Version &&
                r.PackagePattern.Equals(artifact.Name, artifact.Ecosystem == "nuget" ?
                    StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                !r.Sha256.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase)))
                return BadRequest($"A separate pinned approval has different package bytes: {artifact.Name}@{artifact.Version}.");
        }

        var decisionBatchId = Guid.NewGuid().ToString("N");
        foreach (var entry in application.Packages)
        {
            var artifact = entry.PackageArtifact;
            var existing = rules.FirstOrDefault(r => r.ApplicationId == application.Id &&
                r.PackagePattern.Equals(artifact.Name, artifact.Ecosystem == "nuget" ?
                    StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
                r.Version == artifact.Version && r.Source == artifact.Source && r.Sha256 == artifact.Sha256);
            if (existing == null)
            {
                existing = new TrustRule
                {
                    ApplicationId = application.Id, SupplierId = supplierId, Ecosystem = artifact.Ecosystem,
                    PackagePattern = artifact.Name, Version = artifact.Version, Source = artifact.Source,
                    Sha256 = artifact.Sha256, RequestedByUserId = application.RequestedByUserId,
                    Justification = application.Justification, Status = TrustRuleStatus.Approved,
                    ExpiresAtUtc = expiresAtUtc
                };
                db.TrustRules.Add(existing);
            }
            else
            {
                existing.Status = TrustRuleStatus.Approved;
                existing.ExpiresAtUtc = expiresAtUtc;
                existing.SupplierId = supplierId;
            }
            db.TrustRuleReviews.Add(new TrustRuleReview
            {
                TrustRuleId = existing.Id, TrustRule = existing,
                Decision = TrustRuleStatus.Approved, ReviewerId = userId,
                Reason = reason, ExpiresAtUtc = expiresAtUtc,
                ReportHash = application.ReportHash, DecisionBatchId = decisionBatchId,
                ReviewedAtUtc = now
            });
            artifact.FirstTrustedAtUtc ??= now;
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
        var rules = await db.TrustRules.Where(r => r.ApplicationId == id && r.Status == TrustRuleStatus.Approved).ToListAsync();
        foreach (var rule in rules)
        {
            rule.Status = TrustRuleStatus.Revoked;
            db.TrustRuleReviews.Add(new TrustRuleReview
            {
                TrustRuleId = rule.Id, Decision = TrustRuleStatus.Revoked,
                ReviewerId = userId, Reason = reason, ReportHash = application.ReportHash,
                DecisionBatchId = decisionBatchId, ReviewedAtUtc = decidedAtUtc
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
