using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.AlertMonitoring;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services;

public class CatalogInventoryService(TemplateDbContext db, PackageStatusService packageStatus) : IScopedDependency
{
    public Task PopulateAsync(InventoryViewModel model, bool projectOnly = false) => PopulateAsync(model, projectOnly, false);

    public async Task<List<InventoryProject>> ReadBaselineProjectsAsync(IReadOnlySet<string> stoppedRepositories)
    {
        var model = new InventoryViewModel { Tab = "projects", Scope = "baseline", Ecosystem = "all" };
        await PopulateAsync(model, false, true, stoppedRepositories: stoppedRepositories);
        return model.Projects;
    }

    public Task<PackageRelationshipViewModel> ReadPackageRelationshipAsync(string ecosystem, string name, string source)
        => VulnerabilityAuditSnapshot.ReadAsync(db, async () =>
        {
            var model = new InventoryViewModel { Tab = "dependencies", Scope = "baseline", Ecosystem = ecosystem };
            await PopulateAsync(model, false, true, false, name, source);
            var versions = model.Packages.SelectMany(p => p.Versions).ToList();
            var observed = db.PackageVersions.AsNoTracking().Where(v => v.Ecosystem == ecosystem && v.Source == source);
            var grants = db.Rules.AsNoTracking().Where(r => r.Kind == RuleKind.Approval && r.Ecosystem == ecosystem && r.Source == source);
            var normalizedName = name.ToLowerInvariant();
            observed = ecosystem == "nuget" ? observed.Where(v => v.Name.ToLower() == normalizedName) : observed.Where(v => v.Name == name);
            grants = ecosystem == "nuget" ? grants.Where(r => r.PackagePattern.ToLower() == normalizedName) : grants.Where(r => r.PackagePattern == name);
            var count = await observed.Select(v => v.Version).Distinct().CountAsync();
            var examples = await observed.OrderByDescending(v => v.Id).Take(12).ToListAsync();
            var states = await packageStatus.DescribeAsync(examples.Where(v => versions.All(r => r.Dependency.Version != v.Version))
                .Select(v => new Dependency { Ecosystem = ecosystem, Name = v.Name, Version = v.Version, Source = source }));
            versions.AddRange(states.Select(state => new InventoryVersion
                { Dependency = state.Dependency, State = state, Reason = state.Admission.Reason }));
            return new PackageRelationshipViewModel
            {
                Name = name, Ecosystem = ecosystem, Source = source, Versions = versions,
                Rules = await grants.OrderBy(r => r.Id).ToListAsync(), ObservedVersionCount = count,
                CompleteReportCount = model.CompleteReportCount, IncompleteReports = model.IncompleteReports,
                OldestReportAtUtc = model.OldestReportAtUtc, LatestReportAtUtc = model.LatestReportAtUtc
            };
        });

    private async Task PopulateAsync(InventoryViewModel model, bool projectOnly, bool allProjects,
        bool defaultBranchOnly = true, string? packageName = null, string? packageSource = null,
        IReadOnlySet<string>? stoppedRepositories = null)
    {
        // Select complete snapshots before selecting packages: an empty newer snapshot
        // removes old dependencies, and a NuGet-only snapshot must not replace npm.
        var checks = await db.BuildChecks.AsNoTracking()
            .Where(c => !projectOnly || c.Project == model.Project || model.Repository != null &&
                (c.Project == model.Repository || c.Project!.StartsWith(model.Repository + "//"))).OrderByDescending(c => c.CreatedAtUtc)
            .ThenByDescending(c => c.Id).Select(c => new BuildCheck
            {
                Id = c.Id,
                Project = c.Project,
                Commit = c.Commit,
                Pipeline = c.Pipeline,
                ContextJson = c.ContextJson,
                RunId = c.RunId,
                BatchIndex = c.BatchIndex,
                BatchCount = c.BatchCount,
                ScannedProjectCount = c.ScannedProjectCount,
                CreatedAtUtc = c.CreatedAtUtc,
                GraphJson = c.GraphJson == null ? null : "[]"
            }).ToListAsync();
        var runs = checks.Where(c => !string.IsNullOrWhiteSpace(c.Project) &&
                stoppedRepositories?.Contains(BaselineReviewControls.RepositoryOf(c.Project)) != true &&
                BuildCheckRun.Purpose(c.ContextJson) != "review")
            .Where(c => !allProjects || !defaultBranchOnly || BuildCheckRun.Kind(c.ContextJson) == CheckKind.DefaultBranch)
            .GroupBy(c => c.RunId).Where(g => MatchesScope(g.First(), model.Scope))
            .Where(g => model.Ecosystem == "all" ||
                BuildCheckRun.ReadContext(g.First().ContextJson)?.Ecosystem is not { Length: > 0 } ecosystem ||
                ecosystem == model.Ecosystem).ToList();
        var projects = new Dictionary<string, InventoryProject>(StringComparer.Ordinal);
        var selected = new List<(string Ecosystem, List<BuildCheck> Checks)>();
        foreach (var ecosystem in new[] { "nuget", "npm" }.Where(e => model.Ecosystem == "all" || e == model.Ecosystem))
        {
            var groups = BuildCheckRun.ForEcosystem(runs.SelectMany(run => run).ToList(), ecosystem).GroupBy(c => c.RunId)
                .GroupBy(run => (run.First().Project, Context: BuildCheckRun.ContextKey(run.First())));
            foreach (var group in groups)
            {
                var ordered = group.OrderByDescending(g => g.Max(c => c.CreatedAtUtc))
                    .ThenByDescending(g => g.Max(c => c.Id)).ToList();
                if (!projects.TryGetValue(group.Key.Project!, out var project))
                    projects.Add(group.Key.Project!, project = new InventoryProject { Name = group.Key.Project! });
                if (!BuildCheckRun.IsComplete(ordered[0].ToList())) project.Incomplete = true;
                var complete = ordered.FirstOrDefault(g => BuildCheckRun.IsComplete(g.ToList()));
                if (complete == null) continue;
                var snapshot = complete.ToList();
                selected.Add((ecosystem, snapshot));
                var check = snapshot.OrderByDescending(c => c.CreatedAtUtc).First();
                project.Reports.Add(new InventoryReport(ecosystem, check.Id, check.CreatedAtUtc, check.Commit, check.Pipeline, snapshot.All(c => c.GraphJson != null)));
            }
        }
        var dependencies = new List<BuildCheckDependency>();
        foreach (var ids in selected.SelectMany(s => s.Checks).Select(c => c.Id).Distinct().Chunk(500))
        {
            var query = db.BuildCheckDependencies.AsNoTracking().Where(d => ids.Contains(d.BuildCheckId));
            if (packageName != null)
            {
                var normalizedName = packageName.ToLowerInvariant();
                query = model.Ecosystem == "nuget"
                    ? query.Where(d => d.Name.ToLower() == normalizedName)
                    : query.Where(d => d.Name == packageName);
            }
            if (packageSource != null) query = query.Where(d => d.Source == packageSource);
            dependencies.AddRange(await query.ToListAsync());
        }
        var reports = projects.Values.SelectMany(p => p.Reports).ToList();
        model.CompleteReportCount = reports.Count;
        model.IncompleteReports = projects.Values.Any(p => p.Incomplete);
        model.OldestReportAtUtc = reports.Select(r => (DateTime?)r.CheckedAtUtc).Min();
        model.LatestReportAtUtc = reports.Select(r => (DateTime?)r.CheckedAtUtc).Max();
        var byCheck = dependencies.ToLookup(d => d.BuildCheckId);
        var observations = selected.SelectMany(s => s.Checks.SelectMany(c => byCheck[c.Id]
            .Where(d => d.Ecosystem == s.Ecosystem).Select(d => (Check: c, Dependency: d)))).ToList();
        var groupsByArtifact = observations.GroupBy(o => ArtifactKey(o.Dependency)).ToList();
        var requested = groupsByArtifact.Select(g => g.First().Dependency).Select(d => new Dependency
        {
            Ecosystem = d.Ecosystem,
            Name = d.Name,
            Version = d.Version,
            Source = d.Source
        }).ToList();
        var states = await packageStatus.DescribeAsync(requested);
        var requests = new List<ApplicationPackage>();
        foreach (var ids in dependencies.Where(d => d.PackageVersionId != null).Select(d => d.PackageVersionId!.Value).Distinct().Chunk(500))
        {
            requests.AddRange(await db.ApplicationPackages.AsNoTracking().Include(p => p.Application)
                .Where(p => ids.Contains(p.PackageVersionId) && p.Application.Status == ApplicationStatus.Approved).ToListAsync());
        }
        var versions = new List<InventoryVersion>();
        for (var i = 0; i < requested.Count; i++)
        {
            var dependency = requested[i];
            var observed = groupsByArtifact[i].ToList();
            var artifactIds = observed.Select(o => o.Dependency.PackageVersionId).ToHashSet();
            var state = states[i];
            var advisories = state.Advisories.SelectMany(AdvisoryNames).Distinct().Order().ToList();
            var status = !state.Authorized || state.BlockingAdvisories.Count > 0
                ? InventoryStatus.NonCompliant
                : state.CanAdmit ? InventoryStatus.Compliant : InventoryStatus.Pending;
            var version = new InventoryVersion
            {
                Dependency = dependency,
                Status = status,
                Reason = !state.SourcePermitted ? "Package source is no longer permitted."
                    : state.BlockingAdvisories.Count > 0 ? "Known active vulnerability: " + string.Join(", ", state.BlockingAdvisories.SelectMany(AdvisoryNames).Distinct())
                    : state.Admission.Reason,
                Advisories = advisories,
                State = state,
                Rules = state.Rules.Where(r =>
                    TrustPattern.VersionMatches(r.Version, dependency.Version, dependency.Ecosystem, r.IncludePrerelease)).ToList(),
                Requests = requests.Where(p => artifactIds.Contains(p.PackageVersionId))
                    .Select(p => p.Application).DistinctBy(a => a.Id).ToList(),
                Uses = observed.Select(o => new InventoryUse(o.Check.Project!, o.Check.Id,
                    o.Check.CreatedAtUtc, o.Check.Commit, o.Check.Pipeline)).Distinct().ToList()
            };
            versions.Add(version);
            foreach (var name in version.Uses.Select(u => u.Project).Distinct()) projects[name].Versions.Add(version);
        }
        // Load graph payloads only when opening one project, never for the inventory overview.
        if (!projectOnly && model.Tab == "projects" && model.Project != null && projects.TryGetValue(model.Project, out var opened))
        {
            var selectedRuns = selected.Where(s => s.Checks[0].Project == model.Project &&
                (model.Ecosystem == "all" || s.Ecosystem == model.Ecosystem)).ToList();
            var payloads = new Dictionary<int, string?>();
            foreach (var ids in selectedRuns.SelectMany(s => s.Checks).Select(c => c.Id).Distinct().Chunk(500))
                foreach (var payload in await db.BuildChecks.AsNoTracking().Where(c => ids.Contains(c.Id))
                             .Select(c => new { c.Id, c.GraphJson }).ToListAsync())
                    payloads.Add(payload.Id, payload.GraphJson);
            var graphStates = versions.ToDictionary(v => DependencyIntroductionPaths.Identity(v.Dependency));
            foreach (var selection in selectedRuns)
            {
                if (selection.Checks.Any(c => payloads[c.Id] == null)) continue;
                var parts = selection.Checks.Select(c => DependencyReportGraph.Read(payloads[c.Id]!)).ToList();
                if (selection.Ecosystem == "nuget" && parts.All(p => p.Solution != null))
                {
                    var solution = SolutionDependencyGraph.Assemble(parts.Select(p => p.Solution!).ToList());
                    opened.Solution = new InventorySolution
                    {
                        Graph = solution,
                        Repository = BuildCheckRun.ReadContext(selection.Checks[0].ContextJson)?.Repository ?? string.Empty,
                        CheckId = selection.Checks.OrderByDescending(c => c.CreatedAtUtc).First().Id,
                        Packages = solution.Nodes.Where(n => n.Package != null).Select(n =>
                        {
                            var state = graphStates.GetValueOrDefault(DependencyIntroductionPaths.Identity(n.Package!));
                            return new InventoryGraphNode(n.Id, "package", n.Package, [],
                                state?.DisplayStatus ?? InventoryStatus.Pending, state?.Reason, state?.Advisories ?? [],
                                state?.Uses.Select(u => u.Project).Distinct().Order().ToList() ?? [],
                                state == null ? [] : state.Requests.Select(r => r.Justification)
                                    .Concat(state.Rules.Select(r => r.Justification))
                                    .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct().ToList());
                        }).ToList()
                    };
                    continue;
                }
                if (selection.Ecosystem == "nuget")
                {
                    // An old manifest graph cannot prove the structure of a solution.
                    // Retain the report and package list; never invent missing relationships.
                    for (var i = 0; i < opened.Reports.Count; i++)
                        if (opened.Reports[i].Ecosystem == "nuget") opened.Reports[i] = opened.Reports[i] with { HasGraph = false };
                    continue;
                }
                var nodes = parts.SelectMany(p => p.Manifests ?? []).Where(n => n.Ecosystem == selection.Ecosystem);
                foreach (var graph in nodes.GroupBy(n => n.Scope))
                {
                    opened.Graphs.Add(new InventoryGraph
                    {
                        Project = graph.Key.Project,
                        Ecosystem = graph.Key.Ecosystem,
                        Target = graph.Key.Target,
                        CheckId = selection.Checks.OrderByDescending(c => c.CreatedAtUtc).First().Id,
                        Nodes = graph.Select(n =>
                        {
                            var state = n.Package == null ? null : graphStates.GetValueOrDefault(DependencyIntroductionPaths.Identity(n.Package));
                            return new InventoryGraphNode(n.Id, n.Kind, n.Package, n.Children,
                                state?.DisplayStatus ?? InventoryStatus.Pending, state?.Reason, state?.Advisories ?? [],
                                state?.Uses.Select(u => u.Project).Distinct().Order().ToList() ?? [],
                                state == null ? [] : state.Requests.Select(r => r.Justification)
                                    .Concat(state.Rules.Select(r => r.Justification))
                                    .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct().ToList());
                        }).ToList()
                    });
                }
            }
            opened.Diagnosis = ProjectComplianceDiagnostics.Build(opened);
        }
        var packages = versions.GroupBy(v => (v.Dependency.Ecosystem,
                Name: v.Dependency.Ecosystem == "nuget" ? v.Dependency.Name.ToLowerInvariant() : v.Dependency.Name, v.Dependency.Source))
            .Select(g => new InventoryPackage
            {
                Name = g.First().Dependency.Name,
                Ecosystem = g.Key.Ecosystem,
                Source = g.Key.Source,
                Versions = g.OrderBy(v => v.Dependency.Version, StringComparer.Ordinal).ToList()
            }).OrderBy(p => p.Name, StringComparer.Ordinal).ToList();
        model.Summary = new InventorySummary
        {
            ProjectCount = projects.Count,
            PackageCount = packages.Count,
            VulnerablePackageCount = packages.Count(p => p.Versions.Any(v => v.Advisories.Count > 0)),
            VulnerableProjectCount = projects.Values.Count(p => p.Versions.Any(v => v.Advisories.Count > 0)),
            RiskAcceptedProjectCount = projects.Values.Count(p => p.Versions.Any(v => v.State?.AcceptedVulnerabilities.Count > 0)),
            ProjectStatuses = projects.Values.GroupBy(p => p.Status).ToDictionary(g => g.Key, g => g.Count()),
            PackageStatuses = packages.GroupBy(p => p.Status).ToDictionary(g => g.Key, g => g.Count()),
            LatestReportUtc = projects.Values.SelectMany(p => p.Reports).Select(r => (DateTime?)r.CheckedAtUtc).Max(),
            PriorityPackages = packages.Where(p => p.Status != InventoryStatus.Compliant)
                .OrderByDescending(p => p.Versions.Any(v => v.Advisories.Count > 0))
                .ThenByDescending(p => p.Status).ThenByDescending(p => p.AffectedProjectCount).ThenBy(p => p.Name, StringComparer.Ordinal).Take(5).ToList(),
            PriorityProjects = projects.Values.Where(p => p.Status != InventoryStatus.Compliant)
                .OrderByDescending(p => p.Versions.Any(v => v.Advisories.Count > 0))
                .ThenByDescending(p => p.Status).ThenByDescending(p => p.Versions.Count(v => v.Status != InventoryStatus.Compliant))
                .ThenBy(p => p.Name, StringComparer.Ordinal).Take(5).ToList()
        };
        model.PackageCount = packages.Count;
        model.ProjectCount = projects.Count;
        model.ProblemCount = packages.Count(p => p.Status == InventoryStatus.NonCompliant);
        bool VersionMatches(InventoryVersion version) => (model.Ecosystem == "all" || version.Dependency.Ecosystem == model.Ecosystem) &&
            (model.Project == null || version.Uses.Any(u => u.Project == model.Project)) &&
            (Contains(version.Dependency.Name, model.Query) || Contains(version.Dependency.Source, model.Query) ||
             version.Rules.Any(r => Contains(r.Justification, model.Query)) ||
             version.Requests.Any(r => Contains(r.Justification, model.Query) || Contains(r.Project, model.Query)) ||
             version.Uses.Any(u => Contains(u.Project, model.Query))) &&
            MatchesFilter(version.DisplayStatus, version.Advisories.Count > 0, version.State?.AcceptedVulnerabilities.Count > 0, model.Filter);
        if (model.Tab == "dependencies")
        {
            var filtered = packages.Where(p => p.Versions.Any(VersionMatches)).ToList();
            model.Total = filtered.Count;
            model.Page = Math.Min(model.Page, model.PageCount);
            model.Packages = allProjects ? filtered : filtered.Skip((model.Page - 1) * InventoryViewModel.PageSize).Take(InventoryViewModel.PageSize).ToList();
        }
        else
        {
            var filtered = projects.Values.Where(p => model.Project == null || p.Name == model.Project)
                .Where(p => MatchesFilter(p.DisplayStatus, p.Versions.Any(v => v.Advisories.Count > 0), p.Versions.Any(v => v.State?.AcceptedVulnerabilities.Count > 0), model.Filter))
                .Where(p => Contains(p.Name, model.Query) || p.Versions.Any(v =>
                    Contains(v.Dependency.Name, model.Query) || v.Rules.Any(r => Contains(r.Justification, model.Query)) ||
                    v.Requests.Any(r => Contains(r.Justification, model.Query))))
                .OrderByDescending(p => p.DisplayStatus)
                .ThenByDescending(p => p.Versions.Any(v => v.State?.BlockingAdvisories.Count > 0))
                .ThenByDescending(p => p.Versions.Count(v => v.Status == InventoryStatus.NonCompliant))
                .ThenBy(p => p.Name, StringComparer.Ordinal).ToList();
            model.Total = filtered.Count;
            model.Page = Math.Min(model.Page, model.PageCount);
            model.Projects = allProjects ? filtered : filtered.Skip((model.Page - 1) * InventoryViewModel.PageSize).Take(InventoryViewModel.PageSize).ToList();
        }
    }

    private static bool MatchesScope(BuildCheck check, string scope) => scope == "history"
        ? BuildCheckRun.Purpose(check.ContextJson) == null : BuildCheckRun.Purpose(check.ContextJson) == scope;

    private static string ArtifactKey(BuildCheckDependency d) =>
        TrustService.Identity(d.Ecosystem, d.Name, d.Version, d.Source);

    private static bool Contains(string? value, string? query) => string.IsNullOrEmpty(query) ||
        value?.Contains(query, StringComparison.OrdinalIgnoreCase) == true;

    private static bool MatchesFilter(InventoryStatus status, bool hasCve, bool hasRiskAccepted, string filter) => filter switch
    {
        "issues" => status == InventoryStatus.NonCompliant,
        "pending" => status == InventoryStatus.Pending,
        "compliant" => status == InventoryStatus.Compliant,
        "cve" => hasCve,
        "risk-accepted" => hasRiskAccepted,
        _ => true
    };

    private static IEnumerable<string> AdvisoryNames(Entities.Vulnerability vulnerability)
    {
        string[] aliases;
        try { aliases = JsonSerializer.Deserialize<string[]>(vulnerability.Aliases) ?? []; }
        catch (JsonException) { aliases = []; }
        var cves = aliases.Where(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).ToList();
        return cves.Count > 0 ? cves : [vulnerability.SourceId];
    }
}
