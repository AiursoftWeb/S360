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
    TrustService trust) : Controller
{
    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    public Task<IActionResult> Index(int page = 1) => RenderRequests(showForm: true, showHistory: true, page);

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpGet]
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Dependencies", CascadedLinksIcon = "package", CascadedLinksOrder = 1,
        LinkText = "Request a new dependency", LinkOrder = 1)]
    public Task<IActionResult> Create() => RenderRequests(showForm: true, showHistory: false);

    [Authorize(Policy = AppPermissionNames.CanSubmitDependencyRequests)]
    [HttpGet]
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Dependencies", CascadedLinksIcon = "package", CascadedLinksOrder = 1,
        LinkText = "My requests", LinkOrder = 3)]
    public Task<IActionResult> History(int page = 1) => RenderRequests(showForm: false, showHistory: true, page);

    private async Task<IActionResult> RenderRequests(bool showForm, bool showHistory, int page = 1)
    {
        if (page is < 1 or > 10000) return BadRequest();
        var userId = users.GetUserId(User);
        if (userId == null) return Unauthorized();
        var query = db.DependencyApplications.AsNoTracking().Where(a => a.RequestedByUserId == userId);
        var total = showHistory ? await query.CountAsync() : 0;
        page = Math.Min(page, Math.Max(1, (total + 49) / 50));
        var model = new MyRequestsViewModel
        {
            ShowCreateForm = showForm,
            ShowHistory = showHistory,
            PageTitle = showHistory ? "My dependency requests" : "Request a new dependency",
            Page = page, Total = total,
            Applications = showHistory ? await query
                .OrderByDescending(a => a.CreatedAtUtc).ThenByDescending(a => a.Id)
                .Skip((page - 1) * 50).Take(50).ToListAsync() : [],
            NuGetSources = configuration.GetSection("SupplyChain:NuGetSources").Get<string[]>()?.ToList() ?? [],
            NpmSources = configuration.GetSection("SupplyChain:NpmSources").Get<string[]>()?.ToList() ?? []
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
            var reportEdges = await db.ApplicationEdges.AsNoTracking()
                .Where(e => visibleIds.Contains(e.ApplicationId)).ToListAsync();
            var pathsByApplication = reportPackages.GroupBy(p => p.ApplicationId).ToDictionary(
                group => group.Key,
                group => ApplicationPaths.Build(reportEdges.Where(e => e.ApplicationId == group.Key),
                    group.ToDictionary(p => p.PackageArtifactId, p => p.PackageArtifact)));
            var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active).ToListAsync();
            foreach (var package in reportPackages)
            {
                var artifact = package.PackageArtifact;
                var block = BlockRulePolicy.Match(blocks, artifact.Ecosystem, artifact.Name, artifact.Version);
                if (block != null && !model.CurrentBlockReasons.ContainsKey(package.ApplicationId))
                    model.CurrentBlockReasons[package.ApplicationId] =
                        BlockRulePolicy.Explain(block, artifact.Name, artifact.Version,
                            pathsByApplication[package.ApplicationId].GetValueOrDefault(artifact.Id, artifact.Name));
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
        var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active && b.Ecosystem == ecosystem).ToListAsync();
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
            RequestedByUserId = userId, Ecosystem = ecosystem, Source = normalized,
            DirectPackages = JsonSerializer.Serialize(direct), Justification = justification,
            Project = project, ResolutionContext = ecosystem == "nuget" ? "net10.0; pending" : "npm; pending",
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
            .Include(a => a.Packages).ThenInclude(p => p.PackageArtifact)
            .Include(a => a.Edges).FirstOrDefaultAsync(a => a.Id == id);
        if (application == null) return NotFound();
        var isOwner = application.RequestedByUserId == users.GetUserId(User);
        var canReadAll = (await authorization.AuthorizeAsync(User, AppPermissionNames.CanReadSupplyChain)).Succeeded;
        if (!isOwner && !canReadAll) return Forbid();
        var artifacts = application.Packages
            .Select(p => p.PackageArtifact).ToDictionary(a => a.Id);
        var paths = ApplicationPaths.Build(application.Edges, artifacts);
        var model = new RequestDetailsViewModel { Application = application };
        if (isOwner && application.Status == ApplicationStatus.Failed &&
            (await authorization.AuthorizeAsync(User, AppPermissionNames.CanSubmitDependencyRequests)).Succeeded)
        {
            try
            {
                var direct = JsonSerializer.Deserialize<List<DirectPackage>>(application.DirectPackages);
                if (direct is { Count: > 0 })
                    model.RetryDirectPackages = string.Join('\n', direct.Select(p => $"{p.Name}@{p.Version}"));
            }
            catch (JsonException)
            {
                // Older or incomplete failed requests remain readable without offering an invalid retry.
            }
        }
        var packages = application.Packages.ToList();
        var dependencies = packages.Select(package => new Dependency
        {
            Ecosystem = package.PackageArtifact.Ecosystem, Name = package.PackageArtifact.Name,
            Version = package.PackageArtifact.Version, Source = package.PackageArtifact.Source,
            Sha256 = package.PackageArtifact.Sha256
        }).ToList();
        var decisions = await trust.AssessAsync(dependencies);
        var rules = await db.TrustRules.AsNoTracking().Where(r => r.Status != TrustRuleStatus.Pending).ToListAsync();
        var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var now = DateTime.UtcNow;
        for (var i = 0; i < packages.Count; i++)
        {
            var package = packages[i];
            var artifact = package.PackageArtifact;
            var authorizationDecision = TrustService.Evaluate(dependencies[i], rules, blocks, now, exclusions);
            var sourcePermitted = AllowedPackageSources.Contains(configuration, artifact.Ecosystem, artifact.Source);
            var sourceReason = "Package source is no longer permitted for S360 checks.";
            model.Packages.Add(new RequestPackageLine
            {
                Artifact = artifact, IsDirect = package.IsDirect, SourcePermitted = sourcePermitted,
                AlreadyAuthorized = sourcePermitted && authorizationDecision.Trusted,
                AuthorizationReason = sourcePermitted ? authorizationDecision.Reason : sourceReason,
                CheckReady = sourcePermitted && decisions[i].Trusted,
                CheckReason = sourcePermitted ? decisions[i].Reason : sourceReason,
                Path = paths.GetValueOrDefault(artifact.Id, artifact.Name)
            });
        }
        model.Packages = model.Packages.OrderByDescending(p => p.IsDirect).ThenBy(p => p.Artifact.Name).ToList();
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
