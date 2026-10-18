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

[Authorize]
[LimitPerMin]
public class SupplyChainController(TemplateDbContext db, UserManager<User> users, TrustService trust,
    IConfiguration configuration, CatalogInventoryService inventory, IAuthorizationService authorization) : Controller
{
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Dependencies", CascadedLinksIcon = "package", CascadedLinksOrder = 1,
        LinkText = "Dependency catalog", LinkOrder = 2)]
    public async Task<IActionResult> Index(string ecosystem = "all", string? query = null, int? supplierId = null,
        string? lookupName = null, string? lookupVersion = null, string? lookupSource = null,
        string tab = "projects", string scope = "baseline", string filter = "all", string? project = null, int page = 1)
        => await VulnerabilityAuditSnapshot.ExecuteAsync(db, () => IndexSnapshotAsync(ecosystem, query, supplierId,
            lookupName, lookupVersion, lookupSource, tab, scope, filter, project, page));

    private async Task<IActionResult> IndexSnapshotAsync(string ecosystem, string? query, int? supplierId,
        string? lookupName, string? lookupVersion, string? lookupSource, string tab, string scope,
        string filter, string? project, int page)
    {
        if (tab is not ("dependencies" or "projects" or "rules") ||
            ecosystem is not ("all" or "nuget" or "npm") || scope is not ("baseline" or "review" or "history") ||
            filter is not ("all" or "issues" or "pending" or "compliant" or "cve") ||
            page is < 1 or > 10000 || query?.Length > 214 || project?.Length > 200) return BadRequest();
        if (tab != "rules" && lookupName == null && lookupVersion == null && lookupSource == null && supplierId == null)
        {
            var inventoryModel = new InventoryViewModel
            {
                Tab = tab, Scope = scope, Ecosystem = ecosystem, Filter = filter,
                Query = query?.Trim(), Project = string.IsNullOrWhiteSpace(project) ? null : project.Trim(), Page = page,
                CanRead = (await authorization.AuthorizeAsync(User, AppPermissionNames.CanReadSupplyChain)).Succeeded
            };
            if (inventoryModel.CanRead) await inventory.PopulateAsync(inventoryModel);
            return this.StackView(new CatalogViewModel { Inventory = inventoryModel });
        }
        if (ecosystem == "all") ecosystem = "nuget";
        if (supplierId is < 1) return BadRequest();
        query = query?.Trim();
        if (query?.Length > 214) return BadRequest();
        if (lookupName != null && (!TrustPattern.IsValid(lookupName) || lookupName.Contains('*') ||
            string.IsNullOrWhiteSpace(lookupVersion) || lookupVersion.Contains('*') ||
            !TrustPattern.IsValidVersionPattern(lookupVersion) || string.IsNullOrWhiteSpace(lookupSource)))
            return BadRequest("Enter an exact package, version, and HTTPS source.");
        if (lookupName == null && (lookupVersion != null || lookupSource != null)) return BadRequest();
        if (lookupName != null)
        {
            try { lookupSource = TrustPattern.NormalizeSource(lookupSource!); }
            catch (ArgumentException) { return BadRequest("Invalid package source."); }
        }
        var allowedSources = configuration.GetSection(ecosystem == "nuget"
                ? "SupplyChain:NuGetSources" : "SupplyChain:NpmSources")
            .Get<string[]>()?.Select(TrustPattern.NormalizeSource).Distinct().ToArray() ?? [];
        var now = DateTime.UtcNow;
        var allRules = await db.TrustRules.AsNoTracking().Include(r => r.Supplier)
            .Where(r => r.Ecosystem == ecosystem && r.Status != TrustRuleStatus.Pending).ToListAsync();
        var activeApprovedRules = allRules.Where(r => allowedSources.Contains(r.Source) &&
            r.Status == TrustRuleStatus.Approved &&
            (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now)).OrderBy(r => r.PackagePattern).ToList();
        var audit = await db.VulnerabilitySyncStates.AsNoTracking()
            .Select(s => new { s.LastAttemptAtUtc, s.LastSuccessfulAttemptAtUtc, s.LastSuccessAtUtc, s.LastError }).FirstOrDefaultAsync();
        var auditStartedAtUtc = audit?.LastSuccessfulAttemptAtUtc;
        var completedAuditAtUtc = audit?.LastSuccessAtUtc;
        var auditStatus = completedAuditAtUtc == null || auditStartedAtUtc == null
            ? CatalogAuditStatus.Missing
            : completedAuditAtUtc <= now.AddHours(-12)
                ? CatalogAuditStatus.Stale
                : CatalogAuditStatus.Current;
        var artifactQuery = db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == ecosystem &&
            allowedSources.Contains(a.Source) &&
            a.FirstTrustedAtUtc != null && a.SourceVerifiedAtUtc != null && a.LastCheckedAtUtc != null &&
            a.LastCheckedAtUtc >= auditStartedAtUtc && a.LastCheckedAtUtc <= completedAuditAtUtc &&
            !db.VulnerabilityMatches.Any(m => m.PackageArtifactId == a.Id && m.Active &&
                !m.Vulnerability.Withdrawn));
        if (auditStatus != CatalogAuditStatus.Current) artifactQuery = artifactQuery.Where(_ => false);
        if (!string.IsNullOrEmpty(query)) artifactQuery = artifactQuery.Where(a => a.Name.Contains(query));
        var blocks = await db.BlockRules.AsNoTracking()
            .Where(b => b.Ecosystem == ecosystem && b.Active).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var conflictingVerified = TrustService.ConflictingVerifiedIdentities(await db.PackageArtifacts.AsNoTracking()
            .Where(a => a.Ecosystem == ecosystem &&
                (a.SourceVerifiedAtUtc != null || a.FirstTrustedAtUtc != null)).ToListAsync());
        var selectedRules = supplierId == null ? null : activeApprovedRules.Where(r => r.SupplierId == supplierId).ToList();
        var available = new List<CatalogArtifactRow>();
        await foreach (var artifact in artifactQuery.OrderBy(a => a.Name).ThenBy(a => a.Id).AsAsyncEnumerable())
        {
            if (!VulnerabilityAuditFreshness.IsCurrent(artifact.LastCheckedAtUtc,
                    auditStartedAtUtc, completedAuditAtUtc, now))
                continue;
            if (conflictingVerified.Contains(TrustService.Identity(artifact.Ecosystem, artifact.Name,
                    artifact.Version, artifact.Source))) continue;
            var dependency = new Dependency
            {
                Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
                Source = artifact.Source, Sha256 = artifact.Sha256
            };
            var decision = TrustService.Evaluate(dependency, allRules, blocks, now, exclusions);
            if (!decision.Trusted) continue;
            var authorizingRule = allRules.FirstOrDefault(r => r.Id == decision.RuleId);
            if (authorizingRule == null) continue;
            var displayRule = selectedRules?.FirstOrDefault(r =>
                r.Source == artifact.Source && TrustPattern.Matches(r.PackagePattern, artifact.Name, ecosystem) &&
                TrustPattern.VersionMatches(r.Version, artifact.Version, ecosystem, r.IncludePrerelease) &&
                (r.Sha256 == null || r.Sha256.Equals(artifact.Sha256, StringComparison.OrdinalIgnoreCase)) &&
                TrustService.MatchingExclusion(r, dependency, exclusions) == null) ?? authorizingRule;
            if (selectedRules != null && displayRule == authorizingRule &&
                !selectedRules.Contains(authorizingRule)) continue;
            available.Add(new CatalogArtifactRow(artifact, displayRule));
            if (available.Count > 500) break;
        }
        var selectedCatalogRules = activeApprovedRules.Where(r => (supplierId == null || r.SupplierId == supplierId) &&
            (string.IsNullOrEmpty(query) || TrustPattern.Matches(r.PackagePattern, query, ecosystem) ||
             r.PackagePattern.Contains(query, StringComparison.OrdinalIgnoreCase))).ToList();
        var model = new CatalogViewModel
        {
            Ecosystem = ecosystem, Query = query, SupplierId = supplierId,
            LookupName = lookupName, LookupVersion = lookupVersion, LookupSource = lookupSource,
            AuditStatus = auditStatus,
            LatestAuditFailed = VulnerabilityAuditFreshness.HasFailedLatestAttempt(
                audit?.LastAttemptAtUtc, completedAuditAtUtc, audit?.LastError),
            Rules = selectedCatalogRules.Take(500).ToList(),
            Artifacts = available.Take(500).ToList(),
            ResultsTruncated = selectedCatalogRules.Count > 500 || available.Count > 500,
            Suppliers = await db.Suppliers.AsNoTracking().OrderBy(s => s.Name).ToListAsync()
        };
        foreach (var rule in model.Rules.Where(r => !r.PackagePattern.Contains('*') &&
                     !r.Version.Contains('*')))
        {
            var block = BlockRulePolicy.Match(blocks, rule.Ecosystem, rule.PackagePattern, rule.Version);
            if (block != null)
                model.BlockedRuleReasons[rule.Id] = BlockRulePolicy.Explain(block,
                    rule.PackagePattern, rule.Version, rule.PackagePattern);
        }
        if (lookupName != null)
        {
            var selectedName = lookupName;
            var selectedVersion = lookupVersion!;
            var selectedSource = lookupSource!;
            var block = blocks.FirstOrDefault(b => TrustPattern.Matches(b.PackagePattern, selectedName, ecosystem) &&
                TrustPattern.VersionMatches(b.Version, selectedVersion, ecosystem, true));
            if (block != null)
            {
                model.LookupStatus = "Blocked";
                model.LookupReason = $"{block.PackagePattern}: {block.Reason}";
            }
            else if (!allowedSources.Contains(selectedSource))
            {
                model.LookupStatus = "Source not permitted";
                model.LookupReason = "This package registry is no longer configured for S360 checks.";
            }
            else if (conflictingVerified.Contains(TrustService.Identity(ecosystem, selectedName,
                         selectedVersion, selectedSource)))
            {
                model.LookupStatus = "Conflicting package hashes";
                model.LookupReason = "Previously verified package files for this name, version and source have different SHA-256 values. Checks are refused until an administrator investigates.";
            }
            else
            {
                var matching = await db.TrustRules.AsNoTracking()
                    .Where(r => r.Ecosystem == ecosystem && r.Source == selectedSource).ToListAsync();
                matching = matching.Where(r => TrustPattern.Matches(r.PackagePattern, selectedName, ecosystem) &&
                    TrustPattern.VersionMatches(r.Version, selectedVersion, ecosystem, r.IncludePrerelease)).ToList();
                var denied = matching.FirstOrDefault(r => r.Status is TrustRuleStatus.Rejected or TrustRuleStatus.Revoked);
                var activeApproved = matching.Where(r => r.Status == TrustRuleStatus.Approved &&
                    (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now)).ToList();
                var lookupDependency = new Dependency
                {
                    Ecosystem = ecosystem, Name = selectedName, Version = selectedVersion, Source = selectedSource
                };
                var excluded = activeApproved.Select(r => TrustService.MatchingExclusion(r, lookupDependency, exclusions))
                    .FirstOrDefault(e => e != null);
                if (denied != null)
                {
                    model.LookupStatus = "Denied";
                    model.LookupReason = "An explicit rejection or revocation matches this dependency.";
                }
                else if (excluded != null)
                {
                    model.LookupStatus = "Excluded version";
                    model.LookupReason = $"An active rule excludes this version because of {excluded.Vulnerability.SourceId}. Other overlapping approvals cannot override the exclusion.";
                }
                else if (activeApproved.Count > 0)
                {
                    var knownArtifacts = await db.PackageArtifacts.AsNoTracking()
                        .Where(a => a.Ecosystem == ecosystem && a.Version == selectedVersion &&
                            a.Source == selectedSource && a.FirstTrustedAtUtc != null &&
                            (ecosystem == "nuget" ? a.Name.ToLower() == selectedName.ToLower() :
                                a.Name == selectedName))
                        .ToListAsync();
                    var knownDecisions = knownArtifacts.Count == 0 ? [] : await trust.AssessAsync(
                        knownArtifacts.Select(a => new Dependency
                        {
                            Ecosystem = a.Ecosystem, Name = a.Name, Version = a.Version,
                            Source = a.Source, Sha256 = a.Sha256
                        }));
                    var availableArtifact = knownArtifacts.Zip(knownDecisions)
                        .FirstOrDefault(pair => pair.Second.Trusted).First;
                    if (availableArtifact != null)
                    {
                        model.LookupStatus = "Checked artifact available";
                        model.LookupReason = $"Recorded SHA-256: {availableArtifact.Sha256}. " +
                            "This result covers this package file, not its future dependency graph.";
                    }
                    else if (knownDecisions.Count > 0)
                    {
                        model.LookupStatus = "Recorded artifact not currently available";
                        model.LookupReason = knownDecisions[0].Reason;
                    }
                    else
                    {
                        var approved = activeApproved[0];
                        model.LookupStatus = "Rule match — pending artifact and vulnerability check";
                        model.LookupReason = approved.Sha256 == null
                            ? $"Rule #{approved.Id} matches. This does not approve an unseen package file or its dependencies."
                            : $"Pinned rule #{approved.Id} matches the name and version; the package SHA-256 must also match.";
                    }
                }
                else
                {
                    model.LookupStatus = "No active authorization";
                    model.LookupReason = "Submit a dependency request or ask an administrator to review the rule.";
                }
            }
        }
        return this.StackView(model);
    }

    [HttpGet]
    public async Task<IActionResult> Details(int id)
        => await VulnerabilityAuditSnapshot.ExecuteAsync(db, () => DetailsSnapshotAsync(id));

    private async Task<IActionResult> DetailsSnapshotAsync(int id)
    {
        if (id < 1) return BadRequest();
        var artifact = await db.PackageArtifacts.AsNoTracking().SingleOrDefaultAsync(a => a.Id == id);
        if (artifact?.FirstTrustedAtUtc == null) return NotFound();
        if (!AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source)) return NotFound();
        var decision = (await trust.AssessAsync([new Dependency
        {
            Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
            Source = artifact.Source, Sha256 = artifact.Sha256
        }])).Single();
        if (!decision.Trusted || decision.RuleId == null) return NotFound();
        var rule = await db.TrustRules.AsNoTracking().Include(r => r.Supplier).Include(r => r.Reviews)
            .SingleOrDefaultAsync(r => r.Id == decision.RuleId);
        if (rule == null) return NotFound();

        // These edges are evidence from approved request reports, not a guarantee that
        // a future restore will resolve the same graph or that every child is currently allowed.
        var children = await db.ApplicationEdges.AsNoTracking()
            .Where(e => e.ParentPackageId == id && e.Application.Status == ApplicationStatus.Approved)
            .Select(e => new { e.ChildPackage.Name, e.ChildPackage.Version, e.ChildPackage.Source })
            .Distinct().OrderBy(e => e.Name).ThenBy(e => e.Version).Take(101).ToListAsync();
        var parents = await db.ApplicationEdges.AsNoTracking()
            .Where(e => e.ChildPackageId == id && e.ParentPackageId != null &&
                e.Application.Status == ApplicationStatus.Approved)
            .Select(e => new { e.ParentPackage!.Name, e.ParentPackage.Version, e.ParentPackage.Source })
            .Distinct().OrderBy(e => e.Name).ThenBy(e => e.Version).Take(101).ToListAsync();
        return this.StackView(new CatalogArtifactDetailsViewModel
        {
            Artifact = artifact, Rule = rule,
            LatestApproval = rule.Reviews.Where(r => r.Decision == TrustRuleStatus.Approved)
                .OrderByDescending(r => r.ReviewedAtUtc).FirstOrDefault(),
            RecordedChildren = children.Take(100).Select(e => new CatalogRelatedPackage(e.Name, e.Version, e.Source)).ToList(),
            RecordedParents = parents.Take(100).Select(e => new CatalogRelatedPackage(e.Name, e.Version, e.Source)).ToList(),
            ChildrenLimited = children.Count > 100, ParentsLimited = parents.Count > 100
        });
    }

    [Authorize(Policy = AppPermissionNames.CanManageBlocklist)]
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Policies", CascadedLinksIcon = "clipboard-check", CascadedLinksOrder = 2,
        LinkText = "Absolute blocklist", LinkOrder = 2)]
    public async Task<IActionResult> Blocklist(string ecosystem = "nuget")
    {
        if (ecosystem is not ("nuget" or "npm")) return BadRequest();
        var rules = await db.BlockRules.AsNoTracking().Include(b => b.Changes)
            .Where(b => b.Ecosystem == ecosystem)
            .OrderByDescending(b => b.Active).ThenByDescending(b => b.CreatedAtUtc)
            .Take(201).ToListAsync();
        var artifacts = await db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == ecosystem)
            .OrderByDescending(a => a.Id).Select(a => new { a.Id, a.Name, a.Version })
            .Take(5001).ToListAsync();
        var applicationPackages = await db.ApplicationPackages.AsNoTracking()
            .Where(p => p.PackageArtifact.Ecosystem == ecosystem)
            .OrderByDescending(p => p.Id)
            .Select(p => new { p.ApplicationId, p.PackageArtifactId }).Take(5001).ToListAsync();
        var checkDependencies = await db.BuildCheckDependencies.AsNoTracking()
            .Where(d => d.Ecosystem == ecosystem).OrderByDescending(d => d.Id)
            .Select(d => new { d.Name, d.Version, d.BuildCheck.RunId })
            .Take(5001).ToListAsync();
        var model = new BlocklistViewModel
        {
            Ecosystem = ecosystem, Rules = rules.Take(200).ToList(), RulesLimited = rules.Count > 200,
            PreviewLimited = artifacts.Count > 5000 || applicationPackages.Count > 5000 ||
                checkDependencies.Count > 5000
        };
        foreach (var rule in model.Rules.Where(r => r.Active))
        {
            var affected = artifacts.Take(5000).Where(a =>
                TrustPattern.Matches(rule.PackagePattern, a.Name, ecosystem) &&
                TrustPattern.VersionMatches(rule.Version, a.Version, ecosystem, true)).ToList();
            var affectedIds = affected.Select(a => a.Id).ToHashSet();
            model.Impacts[rule.Id] = new BlockRuleImpact(
                affected.Count,
                applicationPackages.Take(5000).Where(p => affectedIds.Contains(p.PackageArtifactId))
                    .Select(p => p.ApplicationId).Distinct().Count(),
                checkDependencies.Take(5000).Where(d =>
                    TrustPattern.Matches(rule.PackagePattern, d.Name, ecosystem) &&
                    TrustPattern.VersionMatches(rule.Version, d.Version, ecosystem, true))
                    .Select(d => d.RunId).Distinct().Count(),
                affected.Select(a => $"{a.Name}@{a.Version}").Distinct().Take(5).ToList());
        }
        return this.StackView(model);
    }

    [Authorize(Policy = AppPermissionNames.CanManageTrustRules)]
    [HttpGet]
    public async Task<IActionResult> PreviewRule(string ecosystem, string packagePattern, string version,
        string source, bool includePrerelease = false)
    {
        if (ecosystem is not ("nuget" or "npm") || !TrustPattern.IsValid(packagePattern) ||
            !TrustPattern.IsValidVersionPattern(version)) return BadRequest();
        string normalizedSource;
        try { normalizedSource = TrustPattern.NormalizeSource(source); }
        catch (ArgumentException) { return BadRequest("Source must be an HTTPS URL."); }
        if (!AllowedPackageSources.Contains(configuration, ecosystem, normalizedSource))
            return BadRequest("Package source is not permitted for trust rules.");

        var namePrefix = packagePattern.EndsWith('*') ? packagePattern[..^1] : packagePattern;
        var versionPrefix = version.EndsWith(".*", StringComparison.Ordinal) ? version[..^1] : version;
        var candidates = db.PackageArtifacts.AsNoTracking()
            .Where(a => a.Ecosystem == ecosystem && a.Source == normalizedSource);
        candidates = ecosystem == "nuget"
            ? packagePattern.EndsWith('*')
                ? candidates.Where(a => a.Name.ToLower().StartsWith(namePrefix.ToLower()))
                : candidates.Where(a => a.Name.ToLower() == namePrefix.ToLower())
            : packagePattern.EndsWith('*')
                ? candidates.Where(a => a.Name.StartsWith(namePrefix))
                : candidates.Where(a => a.Name == namePrefix);
        if (version != "*")
            candidates = version.EndsWith(".*", StringComparison.Ordinal)
                ? candidates.Where(a => a.Version.StartsWith(versionPrefix))
                : candidates.Where(a => a.Version == version);
        var known = await candidates.Select(a => new { a.Name, a.Version })
            .Distinct().OrderBy(a => a.Name).ThenBy(a => a.Version).Take(1001).ToListAsync();
        var matches = known.Where(a => TrustPattern.Matches(packagePattern, a.Name, ecosystem) &&
            TrustPattern.VersionMatches(version, a.Version, ecosystem, includePrerelease))
            .Select(a => new RulePreviewMatch(a.Name, a.Version)).ToList();
        return this.StackView(new RulePreviewViewModel
        {
            Ecosystem = ecosystem, PackagePattern = packagePattern, Version = version,
            Source = normalizedSource, IncludePrerelease = includePrerelease,
            Matches = matches.Take(30).ToList(), CandidateLimitReached = known.Count > 1000,
            ResultLimitReached = matches.Count > 30
        });
    }

    [Authorize(Policy = AppPermissionNames.CanManageTrustRules)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> AddSupplier(string? name)
    {
        name = name?.Trim();
        if (name == null) return BadRequest("Supplier name is required.");
        if (name.Length is < 2 or > 128) return BadRequest("Supplier name must be 2-128 characters.");
        if (!await db.Suppliers.AnyAsync(s => s.Name == name))
        {
            db.Suppliers.Add(new Supplier { Name = name });
            await db.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index), new { tab = "rules" });
    }

    [Authorize(Policy = AppPermissionNames.CanManageTrustRules)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> AddRule(int supplierId, string ecosystem, string packagePattern,
        string version, string source, string? justification, DateTime expiresAtUtc, bool includePrerelease = false)
    {
        expiresAtUtc = UtcExpiry.Normalize(expiresAtUtc);
        if (ecosystem is not ("nuget" or "npm") || !TrustPattern.IsValid(packagePattern) ||
            !TrustPattern.IsValidVersionPattern(version) || justification?.Length is not (>= 10 and <= 2000) ||
            expiresAtUtc <= DateTime.UtcNow || expiresAtUtc > DateTime.UtcNow.AddYears(2) ||
            !await db.Suppliers.AnyAsync(s => s.Id == supplierId)) return BadRequest();
        string normalized;
        try { normalized = TrustPattern.NormalizeSource(source); }
        catch (ArgumentException) { return BadRequest("Source must be an HTTPS URL."); }
        if (!AllowedPackageSources.Contains(configuration, ecosystem, normalized))
            return BadRequest("Package source is not permitted for trust rules.");
        var user = users.GetUserId(User);
        if (user == null) return Unauthorized();
        var rule = new TrustRule
        {
            ApplicationId = null, SupplierId = supplierId, Ecosystem = ecosystem, PackagePattern = packagePattern,
            Version = version, Source = normalized, IncludePrerelease = includePrerelease,
            Justification = justification, RequestedByUserId = user, ExpiresAtUtc = expiresAtUtc,
            Status = TrustRuleStatus.Approved
        };
        db.TrustRuleReviews.Add(new TrustRuleReview
        {
            TrustRuleId = rule.Id, TrustRule = rule,
            Decision = TrustRuleStatus.Approved, ReviewerId = user, Reason = justification,
            ExpiresAtUtc = expiresAtUtc
        });
        db.TrustRules.Add(rule);
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index), new { ecosystem, tab = "rules" });
    }

    [Authorize(Policy = AppPermissionNames.CanManageTrustRules)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeRule(int id, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) return BadRequest();
        var rule = await db.TrustRules.FindAsync(id);
        if (rule == null) return NotFound();
        var user = users.GetUserId(User);
        if (user == null) return Unauthorized();
        rule.Status = TrustRuleStatus.Revoked;
        db.TrustRuleReviews.Add(new TrustRuleReview
        {
            TrustRuleId = id, Decision = TrustRuleStatus.Revoked, ReviewerId = user, Reason = reason
        });
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index), new { rule.Ecosystem, tab = "rules" });
    }

    [Authorize(Policy = AppPermissionNames.CanManageBlocklist)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> AddBlock(string ecosystem, string packagePattern, string version, string? reason)
    {
        if (ecosystem is not ("nuget" or "npm") || !TrustPattern.IsValid(packagePattern) ||
            !TrustPattern.IsValidVersionPattern(version) || reason?.Length is not (>= 10 and <= 2000)) return BadRequest();
        var user = users.GetUserId(User);
        if (user == null) return Unauthorized();
        var block = new BlockRule
        {
            Ecosystem = ecosystem, PackagePattern = packagePattern, Version = version,
            Reason = reason, CreatedByUserId = user
        };
        db.BlockRuleChanges.Add(new BlockRuleChange
        {
            BlockRuleId = block.Id, BlockRule = block, ChangedByUserId = user,
            Description = "Created: " + reason
        });
        db.BlockRules.Add(block);
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Blocklist), new { ecosystem });
    }

    [Authorize(Policy = AppPermissionNames.CanManageBlocklist)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> EditBlock(int id, string packagePattern, string version,
        string reason, string changeReason)
    {
        if (!TrustPattern.IsValid(packagePattern) || !TrustPattern.IsValidVersionPattern(version) ||
            string.IsNullOrWhiteSpace(reason) || reason.Length > 2000 ||
            string.IsNullOrWhiteSpace(changeReason) || changeReason.Length > 1000) return BadRequest();
        var block = await db.BlockRules.FindAsync(id);
        if (block == null) return NotFound();
        if (!block.Active) return BadRequest("Disabled block rules cannot be edited.");
        var user = users.GetUserId(User);
        if (user == null) return Unauthorized();
        var description = $"Reason: {changeReason.Trim()}. Changed {block.PackagePattern} @ {block.Version} " +
                          $"({block.Reason}) to {packagePattern} @ {version} ({reason}).";
        db.BlockRuleChanges.Add(new BlockRuleChange
        {
            BlockRuleId = id, ChangedByUserId = user, Description = description
        });
        block.PackagePattern = packagePattern;
        block.Version = version;
        block.Reason = reason;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Blocklist), new { block.Ecosystem });
    }

    [Authorize(Policy = AppPermissionNames.CanManageBlocklist)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> DisableBlock(int id, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length > 2000) return BadRequest();
        var block = await db.BlockRules.FindAsync(id);
        if (block == null) return NotFound();
        var user = users.GetUserId(User);
        if (user == null) return Unauthorized();
        block.Active = false;
        db.BlockRuleChanges.Add(new BlockRuleChange
        {
            BlockRuleId = id, ChangedByUserId = user, Description = "Disabled: " + reason
        });
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Blocklist), new { block.Ecosystem });
    }
}
