using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services;

/// <summary>
/// Builds an exception-first compliance diagnosis for a single reported project
/// using only the project's already-evaluated versions and recorded dependency graphs.
/// Never invents edges when a graph was not recorded.
/// </summary>
public static class ProjectComplianceDiagnostics
{
    private const int MaxStoredPathsPerPackage = 3;

    public static ProjectDiagnosis Build(InventoryProject project)
    {
        var pathsByIdentity = CollectShortestIntroductionPaths(project);
        var issues = new List<ProjectDiagnosticIssue>();
        var riskAccepted = new List<InventoryVersion>();
        var compliant = new List<InventoryVersion>();

        foreach (var version in project.Versions)
        {
            var state = version.State;
            var isBlocklisted = state?.Blocked == true;
            var blockingAdvisories = state?.BlockingAdvisories
                .SelectMany(AdvisoryNames)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToList() ?? [];
            var hasActiveVulnerability = blockingAdvisories.Count > 0;
            var sourceNotPermitted = state is { SourcePermitted: false };
            var isUnauthorized = state is { Authorized: false } ||
                (state == null && version.Status == InventoryStatus.NonCompliant);
            var needsVerification = version.DisplayStatus == InventoryStatus.Pending;

            if (state?.AcceptedVulnerabilities.Count > 0)
            {
                riskAccepted.Add(version);
            }

            if (version.DisplayStatus == InventoryStatus.Compliant)
            {
                compliant.Add(version);
            }

            if (!isBlocklisted && !hasActiveVulnerability && !sourceNotPermitted && !isUnauthorized && !needsVerification)
            {
                continue;
            }

            var (severity, categoryKey) = isBlocklisted
                ? (ProjectIssueSeverity.Blocklisted, "blocklist")
                : hasActiveVulnerability
                    ? (ProjectIssueSeverity.ActiveVulnerability, "cve")
                    : sourceNotPermitted
                        ? (ProjectIssueSeverity.SourceNotPermitted, "source")
                        : isUnauthorized
                            ? (ProjectIssueSeverity.Unauthorized, "unauthorized")
                            : (ProjectIssueSeverity.NeedsVerification, "verification");

            var identity = DependencyIntroductionPaths.Identity(version.Dependency);
            pathsByIdentity.TryGetValue(identity, out var recordedPaths);
            var orderedPaths = recordedPaths?
                .OrderBy(p => p.HopCount)
                .ThenBy(p => p.DisplayPath, StringComparer.Ordinal)
                .ToList() ?? [];

            var matchedRuleIds = version.Rules.Select(r => r.Id).ToHashSet();
            var otherApprovedRules = state?.Rules
                .Where(r => r.Status == RuleStatus.Approved && !matchedRuleIds.Contains(r.Id))
                .OrderBy(r => r.Version, StringComparer.Ordinal)
                .ThenBy(r => r.Id)
                .ToList() ?? [];

            issues.Add(new ProjectDiagnosticIssue
            {
                Version = version,
                Severity = severity,
                CategoryKey = categoryKey,
                IsBlocklisted = isBlocklisted,
                HasActiveVulnerability = hasActiveVulnerability,
                SourceNotPermitted = sourceNotPermitted,
                IsUnauthorized = isUnauthorized,
                NeedsVerification = needsVerification,
                BlockingAdvisories = blockingAdvisories,
                IntroductionPaths = orderedPaths.Take(MaxStoredPathsPerPackage).Select(p => p.DisplayPath).ToList(),
                IsDirectDependency = orderedPaths.Count > 0 && orderedPaths[0].HopCount == 2,
                TotalPathCount = orderedPaths.Count,
                OtherApprovedRules = otherApprovedRules
            });
        }

        return new ProjectDiagnosis
        {
            BlockingIssues = issues
                .OrderByDescending(i => i.Severity)
                .ThenByDescending(i => i.BlockingAdvisories.Count)
                .ThenBy(i => i.Version.Dependency.Ecosystem, StringComparer.Ordinal)
                .ThenBy(i => i.Version.Dependency.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(i => i.Version.Dependency.Version, StringComparer.Ordinal)
                .ToList(),
            RiskAcceptedVersions = riskAccepted
                .OrderBy(v => v.State!.AcceptedVulnerabilities.Min(a => a.Rule.ExpiresAtUtc ?? DateTime.MaxValue))
                .ThenBy(v => v.Dependency.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(v => v.Dependency.Version, StringComparer.Ordinal)
                .ToList(),
            CompliantVersions = compliant
                .OrderBy(v => v.Dependency.Ecosystem, StringComparer.Ordinal)
                .ThenBy(v => v.Dependency.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(v => v.Dependency.Version, StringComparer.Ordinal)
                .ToList()
        };
    }

    private sealed record RecordedPath(string DisplayPath, int HopCount);

    private static Dictionary<string, List<RecordedPath>> CollectShortestIntroductionPaths(InventoryProject project)
    {
        var result = new Dictionary<string, List<RecordedPath>>(StringComparer.Ordinal);
        var seen = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);

        void Record(Dependency package, List<string> labels)
        {
            var identity = DependencyIntroductionPaths.Identity(package);
            var display = string.Join(" \u2192 ", labels);
            if (!seen.TryGetValue(identity, out var set))
            {
                seen[identity] = set = new HashSet<string>(StringComparer.Ordinal);
                result[identity] = [];
            }

            if (set.Add(display))
            {
                result[identity].Add(new RecordedPath(display, labels.Count));
            }
        }

        // 1. NuGet solution dependency graph (strictly per restore context, never crossing contexts).
        if (project.Solution?.Graph is { } solution)
        {
            var nodesById = solution.Nodes.ToDictionary(n => n.Id, StringComparer.Ordinal);
            foreach (var context in solution.Contexts)
            {
                var rootId = SolutionDependencyGraph.ProjectId(context.ProjectPath);
                if (!nodesById.ContainsKey(rootId)) continue;

                var childrenByParent = context.Edges.ToLookup(e => e.ParentId, e => e.ChildId, StringComparer.Ordinal);
                var parentOf = new Dictionary<string, string?>(StringComparer.Ordinal) { [rootId] = null };
                var queue = new Queue<string>();
                queue.Enqueue(rootId);

                while (queue.TryDequeue(out var currentId))
                {
                    foreach (var childId in childrenByParent[currentId])
                    {
                        if (!nodesById.ContainsKey(childId) || !parentOf.TryAdd(childId, currentId)) continue;
                        queue.Enqueue(childId);

                        var childNode = nodesById[childId];
                        if (childNode.Package == null) continue;

                        var chain = ReconstructChain(childId, parentOf, id =>
                        {
                            var n = nodesById[id];
                            return n.Package != null
                                ? $"{n.Package.Name}@{n.Package.Version}"
                                : n.ProjectPath ?? id;
                        });
                        Record(childNode.Package, chain);
                    }
                }
            }
        }

        // 2. npm / manifest dependency graphs.
        foreach (var graph in project.Graphs)
        {
            var nodesById = graph.Nodes.ToDictionary(n => n.Id, StringComparer.Ordinal);
            var rootNode = graph.Nodes.FirstOrDefault(n => n.Kind == "root");
            if (rootNode == null) continue;

            var parentOf = new Dictionary<string, string?>(StringComparer.Ordinal) { [rootNode.Id] = null };
            var queue = new Queue<string>();
            queue.Enqueue(rootNode.Id);

            while (queue.TryDequeue(out var currentId))
            {
                var currentNode = nodesById[currentId];
                foreach (var childId in currentNode.Children)
                {
                    if (!nodesById.ContainsKey(childId) || !parentOf.TryAdd(childId, currentId)) continue;
                    queue.Enqueue(childId);

                    var childNode = nodesById[childId];
                    if (childNode.Package == null) continue;

                    var chain = ReconstructChain(childId, parentOf, id =>
                    {
                        var n = nodesById[id];
                        if (n.Kind == "root") return string.IsNullOrWhiteSpace(graph.Project) ? "project" : graph.Project;
                        return n.Package != null ? $"{n.Package.Name}@{n.Package.Version}" : id;
                    });
                    Record(childNode.Package, chain);
                }
            }
        }

        return result;
    }

    private static List<string> ReconstructChain(
        string targetId,
        IReadOnlyDictionary<string, string?> parentOf,
        Func<string, string> labelOf)
    {
        var chain = new List<string>();
        var cursor = targetId;
        var guard = 0;
        while (cursor != null && guard++ < 64)
        {
            chain.Add(labelOf(cursor));
            parentOf.TryGetValue(cursor, out cursor);
        }

        chain.Reverse();
        return chain;
    }

    private static IEnumerable<string> AdvisoryNames(Entities.Vulnerability vulnerability)
    {
        string[] aliases;
        try { aliases = JsonSerializer.Deserialize<string[]>(vulnerability.Aliases) ?? []; }
        catch (JsonException) { aliases = []; }
        var cves = aliases.Where(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).ToList();
        return cves.Count > 0 ? cves : [vulnerability.SourceId];
    }
}
