using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services;

public class CatalogInventoryService(TemplateDbContext db, TrustService trust, IConfiguration configuration) : IScopedDependency
{
    public async Task PopulateAsync(InventoryViewModel model)
    {
        // Select complete snapshots before selecting packages: an empty newer snapshot
        // removes old dependencies, and a NuGet-only snapshot must not replace npm.
        var checks = await db.BuildChecks.AsNoTracking().OrderByDescending(c => c.CreatedAtUtc)
            .ThenByDescending(c => c.Id).Select(c => new BuildCheck
            {
                Id = c.Id, Project = c.Project, Commit = c.Commit, Pipeline = c.Pipeline,
                ContextJson = c.ContextJson, RunId = c.RunId, BatchIndex = c.BatchIndex,
                BatchCount = c.BatchCount, ScannedProjectCount = c.ScannedProjectCount,
                CreatedAtUtc = c.CreatedAtUtc, GraphJson = c.GraphJson == null ? null : "[]"
            }).ToListAsync();
        var runs = checks.Where(c => !string.IsNullOrWhiteSpace(c.Project))
            .GroupBy(c => c.RunId).Where(g => MatchesScope(g.First(), model.Scope)).ToList();
        var projects = checks.Where(c => !string.IsNullOrWhiteSpace(c.Project))
            .Select(c => c.Project!).Distinct().ToDictionary(name => name, name => new InventoryProject { Name = name });
        var selected = new List<(string Ecosystem, List<BuildCheck> Checks)>();
        foreach (var ecosystem in new[] { "nuget", "npm" })
        {
            var groups = runs.Where(run => BuildCheckRun.ReadContext(run.First().ContextJson)?.Ecosystem is not { Length: > 0 } scope || scope == ecosystem)
                .GroupBy(run => (run.First().Project, Context: BuildCheckRun.ContextKey(run.First())));
            foreach (var group in groups)
            {
                var ordered = group.OrderByDescending(g => g.Max(c => c.CreatedAtUtc))
                    .ThenByDescending(g => g.Max(c => c.Id)).ToList();
                var project = projects[group.Key.Project!];
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
            dependencies.AddRange(await db.BuildCheckDependencies.AsNoTracking().Where(d => ids.Contains(d.BuildCheckId)).ToListAsync());
        var byCheck = dependencies.ToLookup(d => d.BuildCheckId);
        var observations = selected.SelectMany(s => s.Checks.SelectMany(c => byCheck[c.Id]
            .Where(d => d.Ecosystem == s.Ecosystem).Select(d => (Check: c, Dependency: d)))).ToList();
        var groupsByArtifact = observations.GroupBy(o => ArtifactKey(o.Dependency)).ToList();
        var requested = groupsByArtifact.Select(g => g.First().Dependency).Select(d => new Dependency
        {
            Ecosystem = d.Ecosystem, Name = d.Name, Version = d.Version, Source = d.Source, Sha256 = d.Sha256
        }).ToList();
        var decisions = requested.Count == 0 ? [] : await trust.AssessAsync(requested);
        var rules = await db.TrustRules.AsNoTracking().Where(r => r.Status != TrustRuleStatus.Pending).ToListAsync();
        var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking().Include(e => e.Vulnerability).ToListAsync();
        var matches = new List<VulnerabilityMatch>();
        var requests = new List<ApplicationPackage>();
        foreach (var ids in dependencies.Where(d => d.PackageArtifactId != null).Select(d => d.PackageArtifactId!.Value).Distinct().Chunk(500))
        {
            matches.AddRange(await db.VulnerabilityMatches.AsNoTracking().Include(m => m.Vulnerability)
                .Where(m => ids.Contains(m.PackageArtifactId) && m.Active && !m.Vulnerability.Withdrawn).ToListAsync());
            requests.AddRange(await db.ApplicationPackages.AsNoTracking().Include(p => p.Application)
                .Where(p => ids.Contains(p.PackageArtifactId) && p.Application.Status == ApplicationStatus.Approved).ToListAsync());
        }
        var versions = new List<InventoryVersion>();
        for (var i = 0; i < requested.Count; i++)
        {
            var dependency = requested[i];
            var observed = groupsByArtifact[i].ToList();
            var artifactIds = observed.Select(o => o.Dependency.PackageArtifactId).ToHashSet();
            var advisories = matches.Where(m => artifactIds.Contains(m.PackageArtifactId))
                .SelectMany(m => AdvisoryNames(m.Vulnerability)).Distinct().Order().ToList();
            var policy = TrustService.Evaluate(dependency, rules, blocks, DateTime.UtcNow, exclusions);
            var sourceAllowed = AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source);
            var status = !sourceAllowed || !policy.Trusted || advisories.Count > 0
                ? InventoryStatus.NonCompliant
                : decisions[i].Trusted ? InventoryStatus.Compliant : InventoryStatus.Pending;
            var version = new InventoryVersion
            {
                Dependency = dependency, Status = status,
                Reason = !sourceAllowed ? "Package source is no longer permitted."
                    : advisories.Count > 0 ? "Known active vulnerability: " + string.Join(", ", advisories)
                    : decisions[i].Reason,
                Advisories = advisories,
                Rules = rules.Where(r => r.Ecosystem == dependency.Ecosystem && r.Source == dependency.Source &&
                    TrustPattern.Matches(r.PackagePattern, dependency.Name, dependency.Ecosystem) &&
                    TrustPattern.VersionMatches(r.Version, dependency.Version, dependency.Ecosystem, r.IncludePrerelease)).ToList(),
                Requests = requests.Where(p => artifactIds.Contains(p.PackageArtifactId))
                    .Select(p => p.Application).DistinctBy(a => a.Id).ToList(),
                Uses = observed.Select(o => new InventoryUse(o.Check.Project!, o.Check.Id,
                    o.Check.CreatedAtUtc, o.Check.Commit, o.Check.Pipeline)).Distinct().ToList()
            };
            versions.Add(version);
            foreach (var name in version.Uses.Select(u => u.Project).Distinct()) projects[name].Versions.Add(version);
        }
        // Load graph payloads only when opening one project, never for the inventory overview.
        if (model.Tab == "projects" && model.Project != null && projects.TryGetValue(model.Project, out var opened))
        {
            var selectedRuns = selected.Where(s => s.Checks[0].Project == model.Project &&
                (model.Ecosystem == "all" || s.Ecosystem == model.Ecosystem)).ToList();
            var payloads = new Dictionary<int, string?>();
            foreach (var ids in selectedRuns.SelectMany(s => s.Checks).Select(c => c.Id).Distinct().Chunk(500))
                foreach (var payload in await db.BuildChecks.AsNoTracking().Where(c => ids.Contains(c.Id))
                             .Select(c => new { c.Id, c.GraphJson }).ToListAsync())
                    payloads.Add(payload.Id, payload.GraphJson);
            var states = versions.ToDictionary(v => DependencyIntroductionPaths.Identity(v.Dependency));
            foreach (var selection in selectedRuns)
            {
                if (selection.Checks.Any(c => payloads[c.Id] == null)) continue;
                var nodes = selection.Checks.SelectMany(c =>
                    JsonSerializer.Deserialize<List<DependencyGraphNode>>(payloads[c.Id]!) ?? [])
                    .Where(n => n.Ecosystem == selection.Ecosystem);
                foreach (var graph in nodes.GroupBy(n => n.Scope))
                {
                    opened.Graphs.Add(new InventoryGraph
                    {
                        Project = graph.Key.Project, Ecosystem = graph.Key.Ecosystem, Target = graph.Key.Target,
                        CheckId = selection.Checks.OrderByDescending(c => c.CreatedAtUtc).First().Id,
                        Nodes = graph.Select(n =>
                        {
                            var state = n.Package == null ? null : states.GetValueOrDefault(DependencyIntroductionPaths.Identity(n.Package));
                            return new InventoryGraphNode(n.Id, n.Kind, n.Package, n.Children,
                                state?.Status ?? InventoryStatus.Pending, state?.Reason, state?.Advisories ?? [],
                                state?.Uses.Select(u => u.Project).Distinct().Order().ToList() ?? [],
                                state == null ? [] : state.Requests.Select(r => r.Justification)
                                    .Concat(state.Rules.Select(r => r.Justification))
                                    .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct().ToList());
                        }).ToList()
                    });
                }
            }
        }
        var packages = versions.GroupBy(v => (v.Dependency.Ecosystem,
                Name: v.Dependency.Ecosystem == "nuget" ? v.Dependency.Name.ToLowerInvariant() : v.Dependency.Name, v.Dependency.Source))
            .Select(g => new InventoryPackage { Name = g.First().Dependency.Name, Ecosystem = g.Key.Ecosystem,
                Source = g.Key.Source, Versions = g.OrderBy(v => v.Dependency.Version).ToList() }).OrderBy(p => p.Name).ToList();
        model.PackageCount = packages.Count;
        model.ProjectCount = projects.Values.Count(p => p.Reports.Count > 0);
        model.ProblemCount = packages.Count(p => p.Status == InventoryStatus.NonCompliant);
        bool VersionMatches(InventoryVersion version) => (model.Ecosystem == "all" || version.Dependency.Ecosystem == model.Ecosystem) &&
            (model.Project == null || version.Uses.Any(u => u.Project == model.Project)) &&
            (Contains(version.Dependency.Name, model.Query) || Contains(version.Dependency.Source, model.Query) ||
             version.Rules.Any(r => Contains(r.Justification, model.Query)) ||
             version.Requests.Any(r => Contains(r.Justification, model.Query) || Contains(r.Project, model.Query)) ||
             version.Uses.Any(u => Contains(u.Project, model.Query))) &&
            MatchesFilter(version.Status, version.Advisories.Count > 0, model.Filter);
        if (model.Tab == "dependencies")
        {
            var filtered = packages.Where(p => p.Versions.Any(VersionMatches)).ToList();
            model.Total = filtered.Count;
            model.Page = Math.Min(model.Page, model.PageCount);
            model.Packages = filtered.Skip((model.Page - 1) * InventoryViewModel.PageSize).Take(InventoryViewModel.PageSize).ToList();
        }
        else
        {
            var filtered = projects.Values.Where(p => model.Project == null || p.Name == model.Project)
                .Where(p => MatchesFilter(p.Status, p.Versions.Any(v => v.Advisories.Count > 0), model.Filter))
                .Where(p => Contains(p.Name, model.Query) || p.Versions.Any(v =>
                    Contains(v.Dependency.Name, model.Query) || v.Rules.Any(r => Contains(r.Justification, model.Query)) ||
                    v.Requests.Any(r => Contains(r.Justification, model.Query))))
                .Where(p => model.Ecosystem == "all" || p.Reports.Any(r => r.Ecosystem == model.Ecosystem))
                .OrderByDescending(p => p.Status).ThenBy(p => p.Name).ToList();
            model.Total = filtered.Count;
            model.Page = Math.Min(model.Page, model.PageCount);
            model.Projects = filtered.Skip((model.Page - 1) * InventoryViewModel.PageSize).Take(InventoryViewModel.PageSize).ToList();
        }
    }

    private static bool MatchesScope(BuildCheck check, string scope) => scope == "history"
        ? BuildCheckRun.Purpose(check.ContextJson) == null : BuildCheckRun.Purpose(check.ContextJson) == scope;

    private static string ArtifactKey(BuildCheckDependency d) =>
        TrustService.Identity(d.Ecosystem, d.Name, d.Version, d.Source) + "\n" + d.Sha256.ToLowerInvariant();

    private static bool Contains(string? value, string? query) => string.IsNullOrEmpty(query) ||
        value?.Contains(query, StringComparison.OrdinalIgnoreCase) == true;

    private static bool MatchesFilter(InventoryStatus status, bool hasCve, string filter) => filter switch
    {
        "issues" => status == InventoryStatus.NonCompliant,
        "pending" => status == InventoryStatus.Pending,
        "compliant" => status == InventoryStatus.Compliant,
        "cve" => hasCve,
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
