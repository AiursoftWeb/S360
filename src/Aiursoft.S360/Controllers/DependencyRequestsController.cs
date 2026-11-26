using System.Text.Json;
using Aiursoft.Canon.BackgroundJobs;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.UiStack.Navigation;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Controllers;

[Authorize]
[LimitPerMin]
public class DependencyRequestsController(TemplateDbContext db, UserManager<User> users,
    IConfiguration configuration, BackgroundJobRegistry jobs, IAuthorizationService authorization,
    TrustService trust, DependencyApproverDirectoryService approverDirectory) : Controller
{
    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    public Task<IActionResult> Index(int page = 1, string? ecosystem = null, string? source = null,
        string? package = null, string? project = null)
        => RenderRequests(showForm: true, showHistory: true, page, ecosystem, source, package, project);

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpGet]
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Requests", CascadedLinksIcon = "inbox", CascadedLinksOrder = 3,
        LinkText = "Request a package", LinkOrder = 1)]
    public Task<IActionResult> Create(string? ecosystem = null, string? source = null,
        string? package = null, string? project = null)
        => RenderRequests(showForm: true, showHistory: false, ecosystem: ecosystem, source: source,
            package: package, project: project);

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpGet]
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Requests", CascadedLinksIcon = "inbox", CascadedLinksOrder = 3,
        LinkText = "My requests", LinkOrder = 2)]
    public Task<IActionResult> History(int page = 1) => RenderRequests(showForm: false, showHistory: true, page);

    private async Task<IActionResult> RenderRequests(bool showForm, bool showHistory, int page = 1,
        string? ecosystem = null, string? source = null, string? package = null, string? project = null)
    {
        if (page is < 1 or > 10000) return BadRequest();
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        var query = db.DependencyApplications.AsNoTracking().Where(a => a.RequestedByUserId == userId);
        var total = showHistory ? await query.CountAsync() : 0;
        page = Math.Min(page, Math.Max(1, (total + 49) / 50));

        var nugetSources = configuration.GetSection("SupplyChain:NuGetSources").Get<string[]>()?.ToList() ?? [];
        var npmSources = configuration.GetSection("SupplyChain:NpmSources").Get<string[]>()?.ToList() ?? [];
        var prefillEcosystem = string.Equals(ecosystem, "npm", StringComparison.OrdinalIgnoreCase)
            ? "npm"
            : "nuget";
        string? prefillSource = null;
        if (!string.IsNullOrWhiteSpace(source))
        {
            var trimmedSource = source.Trim();
            var matchedNuget = MatchConfiguredSource(nugetSources, trimmedSource);
            var matchedNpm = MatchConfiguredSource(npmSources, trimmedSource);
            if (prefillEcosystem == "npm" && matchedNpm != null)
            {
                prefillSource = matchedNpm;
            }
            else if (prefillEcosystem == "nuget" && matchedNuget != null)
            {
                prefillSource = matchedNuget;
            }
            else if (string.IsNullOrWhiteSpace(ecosystem) && matchedNpm != null)
            {
                prefillEcosystem = "npm";
                prefillSource = matchedNpm;
            }
            else if (string.IsNullOrWhiteSpace(ecosystem) && matchedNuget != null)
            {
                prefillEcosystem = "nuget";
                prefillSource = matchedNuget;
            }
        }

        var prefillPackages = string.IsNullOrWhiteSpace(package) ? null : package.Trim();
        if (prefillPackages is { Length: > 2000 }) prefillPackages = prefillPackages[..2000];
        var prefillProject = string.IsNullOrWhiteSpace(project) ? null : project.Trim();
        if (prefillProject is { Length: > 200 }) prefillProject = prefillProject[..200];

        var model = new MyRequestsViewModel
        {
            ShowCreateForm = showForm,
            ShowHistory = showHistory,
            PageTitle = showHistory ? "My dependency requests" : "Request a new dependency",
            Page = page,
            Total = total,
            Applications = showHistory ? await query
                .OrderByDescending(a => a.CreatedAtUtc).ThenByDescending(a => a.Id)
                .Skip((page - 1) * 50).Take(50).ToListAsync() : [],
            NuGetSources = nugetSources,
            NpmSources = npmSources,
            PrefillEcosystem = prefillEcosystem,
            PrefillSource = prefillSource,
            PrefillDirectPackages = prefillPackages,
            PrefillProject = prefillProject,
            Approvers = await approverDirectory.GetApproversAsync(),
            CanReview = (await authorization.AuthorizeAsync(User, AppPermissionNames.CanReviewDependencyRequests)).Succeeded,
            CurrentUserId = userId
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
            var blocks = await db.Rules.Where(r => r.Kind == RuleKind.Block).AsNoTracking().Where(b => b.Status == RuleStatus.Approved).ToListAsync();
            foreach (var packageEntry in reportPackages)
            {
                var artifact = packageEntry.PackageVersion;
                var block = BlockRulePolicy.Match(blocks, artifact.Ecosystem, artifact.Name, artifact.Version);
                if (block != null && !model.CurrentBlockReasons.ContainsKey(packageEntry.ApplicationId))
                    model.CurrentBlockReasons[packageEntry.ApplicationId] =
                        BlockRulePolicy.Explain(block, artifact.Name, artifact.Version,
                            artifact.Name);
            }
        }
        return this.StackView(model, nameof(Index));
    }

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit(string ecosystem, string source, string directPackages,
        string justification, string? project = null)
    {
        if (ecosystem is not ("nuget" or "npm") || string.IsNullOrWhiteSpace(justification) ||
            justification.Length > 2000 || project?.Length > 200) return BadRequest();
        string normalized;
        try { normalized = TrustPattern.NormalizeSource(source); }
        catch (ArgumentException) { return BadRequest("Invalid package source."); }
        if (!AllowedPackageSources.Contains(configuration, ecosystem, normalized))
            return BadRequest("Package source is not permitted for employee resolution.");
        var direct = ParseDirectPackages(directPackages, ecosystem);
        if (direct == null) return BadRequest("Enter 1-20 exact dependencies, one name@version per line.");
        var blocks = await db.Rules.Where(r => r.Kind == RuleKind.Block).AsNoTracking().Where(b => b.Status == RuleStatus.Approved && b.Ecosystem == ecosystem).ToListAsync();
        foreach (var package in direct)
        {
            var block = BlockRulePolicy.Match(blocks, ecosystem, package.Name, package.Version);
            if (block != null)
                return BadRequest(BlockRulePolicy.Explain(block, package.Name, package.Version, package.Name));
        }
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        var application = new DependencyApplication
        {
            RequestedByUserId = userId,
            Ecosystem = ecosystem,
            Source = normalized,
            DirectPackages = JsonSerializer.Serialize(direct),
            Justification = justification,
            Project = project,
            ResolutionContext = ecosystem == "nuget" ? "net10.0; pending" : "npm; pending",
            Status = ApplicationStatus.Resolving
        };
        db.DependencyApplications.Add(application);
        await db.SaveChangesAsync();
        jobs.TriggerNow<DependencyResolutionJob>();
        return RedirectToAction(nameof(Details), new { id = application.Id });
    }

    [HttpGet]
    public async Task<IActionResult> Details(int id)
    {
        var application = await db.DependencyApplications.AsNoTracking()
            .Include(a => a.Packages).ThenInclude(p => p.PackageVersion)
            .FirstOrDefaultAsync(a => a.Id == id);
        if (application == null) return NotFound();
        var currentUserId = users.GetUserId(User);
        var isOwner = application.RequestedByUserId == currentUserId;
        var canReadAll = (await authorization.AuthorizeAsync(User, AppPermissionNames.CanReadSupplyChain)).Succeeded;
        if (!isOwner && !canReadAll) return Forbid();
        var canReview = (await authorization.AuthorizeAsync(User, AppPermissionNames.CanReviewDependencyRequests)).Succeeded;
        var reviewPath = Url.Action(nameof(DependencyReviewsController.Index), "DependencyReviews",
            new { filter = "pending" }) ?? "/DependencyReviews/Index?filter=pending";
        var reviewAnchorUrl = $"{Request.Scheme}://{Request.Host}{reviewPath}#request-{application.Id}";

        string? decidedByDisplayName = null;
        if (!string.IsNullOrWhiteSpace(application.DecidedByUserId))
        {
            var decider = await db.Users.AsNoTracking()
                .Where(u => u.Id == application.DecidedByUserId)
                .Select(u => new { u.DisplayName, u.UserName, u.Email })
                .FirstOrDefaultAsync();
            if (decider != null)
            {
                decidedByDisplayName = !string.IsNullOrWhiteSpace(decider.DisplayName)
                    ? decider.DisplayName
                    : decider.UserName ?? decider.Email;
            }
        }

        List<string> directSummaries = [];
        try
        {
            var parsedDirect = JsonSerializer.Deserialize<List<DirectPackage>>(application.DirectPackages);
            if (parsedDirect is { Count: > 0 })
            {
                directSummaries = parsedDirect.Select(p => $"{p.Name}@{p.Version}").ToList();
            }
        }
        catch (JsonException)
        {
            // Older or malformed direct-package payloads stay readable without breaking the details page.
        }

        var model = new RequestDetailsViewModel
        {
            Application = application,
            Approvers = await approverDirectory.GetApproversAsync(),
            CanReview = canReview,
            IsOwner = isOwner,
            CurrentUserId = currentUserId,
            DecidedByDisplayName = decidedByDisplayName,
            DirectPackageSummaries = directSummaries,
            ReviewAnchorUrl = reviewAnchorUrl
        };
        if (isOwner && application.Status == ApplicationStatus.Failed &&
            (await authorization.AuthorizeAsync(User, AppPermissionNames.CanSubmitDependencyRequests)).Succeeded &&
            directSummaries.Count > 0)
        {
            model.RetryDirectPackages = string.Join('\n', directSummaries);
        }
        var packages = application.Packages.ToList();
        var dependencies = packages.Select(package => new Dependency
        {
            Ecosystem = package.PackageVersion.Ecosystem,
            Name = package.PackageVersion.Name,
            Version = package.PackageVersion.Version,
            Source = package.PackageVersion.Source,

        }).ToList();
        var decisions = await trust.AssessAsync(dependencies);
        var rules = await db.Rules.Where(r => r.Kind == RuleKind.Approval).AsNoTracking().Where(r => r.Status != RuleStatus.Pending).ToListAsync();
        var blocks = await db.Rules.Where(r => r.Kind == RuleKind.Block).AsNoTracking().Where(b => b.Status == RuleStatus.Approved).ToListAsync();
        var exclusions = await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var now = DateTime.UtcNow;
        for (var i = 0; i < packages.Count; i++)
        {
            var package = packages[i];
            var artifact = package.PackageVersion;
            var authorizationDecision = TrustService.Evaluate(dependencies[i], rules, blocks, now, exclusions);
            var sourcePermitted = AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source);
            var sourceReason = "Package source is no longer permitted for S360 checks.";
            model.Packages.Add(new RequestPackageLine
            {
                Artifact = artifact,
                IsDirect = package.IsDirect,
                SourcePermitted = sourcePermitted,
                AlreadyAuthorized = sourcePermitted && authorizationDecision.Trusted,
                AuthorizationReason = sourcePermitted ? authorizationDecision.Reason : sourceReason,
                CheckReady = sourcePermitted && decisions[i].Trusted,
                CheckReason = sourcePermitted ? decisions[i].Reason : sourceReason,
                Path = artifact.Name
            });
        }
        model.Packages = model.Packages.OrderByDescending(p => p.IsDirect).ThenBy(p => p.Artifact.Name, StringComparer.Ordinal).ToList();
        return this.StackView(model);
    }

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Withdraw(int id)
    {
        var application = await db.DependencyApplications.FindAsync(id);
        if (application == null) return NotFound();
        if (application.RequestedByUserId != users.GetUserId(User)) return Forbid();
        if (application.Status is not (ApplicationStatus.Resolving or ApplicationStatus.ReadyForReview)) return BadRequest();
        application.Status = ApplicationStatus.Withdrawn;
        application.DecidedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    private static string? MatchConfiguredSource(List<string> configuredSources, string candidate)
    {
        var exact = configuredSources.FirstOrDefault(s =>
            string.Equals(s, candidate, StringComparison.OrdinalIgnoreCase));
        if (exact != null) return exact;
        try
        {
            var normalizedCandidate = TrustPattern.NormalizeSource(candidate);
            return configuredSources.FirstOrDefault(s =>
            {
                try
                {
                    return string.Equals(TrustPattern.NormalizeSource(s), normalizedCandidate, StringComparison.OrdinalIgnoreCase);
                }
                catch (ArgumentException)
                {
                    return false;
                }
            });
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static List<DirectPackage>? ParseDirectPackages(string input, string ecosystem)
    {
        if (string.IsNullOrWhiteSpace(input) || input.Length > 2000) return null;
        var result = new List<DirectPackage>();
        foreach (var raw in input.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var index = raw.LastIndexOf('@');
            if (index < 1 || index == raw.Length - 1) return null;
            var name = raw[..index];
            var version = raw[(index + 1)..];
            if (!TrustPattern.IsValidConcretePackage(ecosystem, name, version)) return null;
            result.Add(new DirectPackage(name, version));
        }
        var nameComparer = ecosystem == "nuget" ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        return result.Count is < 1 or > 20 || result.Select(p => p.Name).Distinct(nameComparer).Count() != result.Count
            ? null : result;
    }

}
