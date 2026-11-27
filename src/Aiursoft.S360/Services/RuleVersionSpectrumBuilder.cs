using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Services;

/// <summary>
/// Builds a policy-truthful version spectrum view model from existing S360 rules, blocks,
/// exclusions, active advisory ranges, risk acceptances, and observed versions.
/// Never invents safe version boundaries when advisory ranges cannot be evaluated.
/// </summary>
public static class RuleVersionSpectrumBuilder
{
    public static RuleVersionSpectrumViewModel Build(
        string ecosystem,
        string packageName,
        string source,
        PackageRule? focusedRule,
        IReadOnlyCollection<PackageRule> approvals,
        IReadOnlyCollection<PackageRule> blocks,
        IReadOnlyCollection<PackageRule> exclusions,
        IReadOnlyCollection<RuleAdvisoryRange> advisoryRanges,
        IReadOnlyCollection<PackageRule> riskAcceptances,
        PackageRelationshipViewModel? relationship,
        DateTime nowUtc)
    {
        var allApprovals = approvals
            .Concat(focusedRule != null ? [focusedRule] : [])
            .DistinctBy(r => r.Id)
            .OrderByDescending(r => focusedRule != null && r.Id == focusedRule.Id)
            .ThenByDescending(r => IsActiveApproval(r, nowUtc))
            .ThenBy(r => r.Version, StringComparer.Ordinal)
            .ThenBy(r => r.Id)
            .ToList();

        var activeApprovals = allApprovals
            .Where(r => IsActiveApproval(r, nowUtc))
            .ToList();

        var approvalBands = allApprovals
            .Select(r => new SpectrumApprovalBand(
                r.Id,
                r.Version,
                r.Version.Contains('*'),
                r.IncludePrerelease,
                r.Status,
                r.ExpiresAtUtc is { } exp && exp <= nowUtc,
                r.ExpiresAtUtc,
                focusedRule != null && r.Id == focusedRule.Id))
            .ToList();

        var matchingBlocks = blocks
            .Where(b => b.Kind == RuleKind.Block && b.Status == RuleStatus.Approved &&
                b.Ecosystem == ecosystem && TrustPattern.Matches(b.PackagePattern, packageName, ecosystem))
            .OrderBy(b => b.Id)
            .Select(b => new SpectrumBlockBand(b.Id, b.PackagePattern, b.Version, b.Justification))
            .ToList();

        var exclusionBands = exclusions
            .Where(e => e.Kind == RuleKind.VulnerabilityExclusion && e.Vulnerability != null)
            .OrderByDescending(e => e.RequestedAtUtc)
            .ThenBy(e => e.Id)
            .Select(e =>
            {
                var vuln = e.Vulnerability!;
                var parsed = OsvAffectedVersions.Read(vuln.RawAffectedJson, ecosystem, vuln.PackageName);
                var intervals = parsed.Intervals.Select(FormatInterval).ToList();
                var listed = parsed.ListedVersions
                    .OrderBy(v => v, Comparer<string>.Create((a, b) => OsvRangeMatcher.CompareVersions(a, b, ecosystem)))
                    .ToList();
                return new SpectrumExclusionBand(
                    e.Id,
                    e.ParentRuleId,
                    vuln.SourceId,
                    vuln.Url,
                    vuln.Withdrawn,
                    e.Justification,
                    intervals,
                    listed,
                    parsed.HasUnparsedData);
            })
            .ToList();

        var activeExcludedVulnIds = exclusions
            .Where(e => e.Kind == RuleKind.VulnerabilityExclusion && e.Vulnerability is { Withdrawn: false })
            .Select(e => e.VulnerabilityId)
            .OfType<int>()
            .ToHashSet();

        var activeAcceptedVulnIds = riskAcceptances
            .Where(r => r.Kind == RuleKind.RiskAcceptance && r.Status == RuleStatus.Approved &&
                r.ExpiresAtUtc > nowUtc && r.VulnerabilityId.HasValue)
            .Select(r => r.VulnerabilityId!.Value)
            .ToHashSet();

        var advisoryBands = advisoryRanges
            .DistinctBy(r => r.Advisory.Id)
            .OrderBy(r => r.Intersection == RangeRisk.Unknown ? 0 : 1)
            .ThenBy(r => r.Advisory.SourceId, StringComparer.Ordinal)
            .Select(r =>
            {
                var vuln = r.Advisory;
                var parsed = OsvAffectedVersions.Read(vuln.RawAffectedJson, ecosystem, vuln.PackageName);
                var intervals = parsed.Intervals.Select(FormatInterval).ToList();
                var listed = parsed.ListedVersions
                    .OrderBy(v => v, Comparer<string>.Create((a, b) => OsvRangeMatcher.CompareVersions(a, b, ecosystem)))
                    .ToList();
                return new SpectrumAdvisoryBand(
                    vuln.SourceId,
                    vuln.Url,
                    vuln.Summary,
                    r.Intersection,
                    intervals,
                    listed,
                    parsed.HasUnparsedData || r.Intersection == RangeRisk.Unknown,
                    activeExcludedVulnIds.Contains(vuln.Id),
                    activeAcceptedVulnIds.Contains(vuln.Id));
            })
            .ToList();

        var riskAcceptanceBands = riskAcceptances
            .Where(r => r.Kind == RuleKind.RiskAcceptance && r.Status == RuleStatus.Approved &&
                r.ExpiresAtUtc > nowUtc)
            .OrderBy(r => r.ExpiresAtUtc)
            .ThenBy(r => r.Id)
            .Select(r => new SpectrumRiskAcceptanceBand(
                r.Id,
                r.Version,
                r.Vulnerability?.SourceId,
                r.Vulnerability?.Url,
                r.Justification,
                r.ExpiresAtUtc))
            .ToList();

        var versionPoints = new List<SpectrumVersionPoint>();
        if (relationship != null)
        {
            var orderedVersions = relationship.Versions
                .Where(v => v.State != null)
                .OrderBy(v => v.Dependency.Version,
                    Comparer<string>.Create((a, b) => OsvRangeMatcher.CompareVersions(a, b, ecosystem)))
                .ToList();

            foreach (var item in orderedVersions)
            {
                var state = item.State!;
                var dep = item.Dependency;
                var withinFocused = focusedRule != null && !focusedRule.IsLegacyTemplate &&
                    TrustPattern.VersionMatches(focusedRule.Version, dep.Version, ecosystem, focusedRule.IncludePrerelease);
                var matchingActiveApprovals = activeApprovals
                    .Where(r => TrustPattern.VersionMatches(r.Version, dep.Version, ecosystem, r.IncludePrerelease))
                    .ToList();
                var withinAnyApproval = matchingActiveApprovals.Count > 0;
                var matchedExclusion = matchingActiveApprovals
                    .Select(r => TrustService.MatchingExclusion(r, dep, exclusions))
                    .FirstOrDefault(e => e != null);

                var fixVersions = state.BlockingAdvisories
                    .SelectMany(v => OsvAffectedVersions.Read(v.RawAffectedJson, ecosystem, v.PackageName).Intervals)
                    .Where(i => i.EndKind == "fixed" && !string.IsNullOrWhiteSpace(i.End))
                    .Select(i => i.End!)
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(v => v, Comparer<string>.Create((a, b) => OsvRangeMatcher.CompareVersions(a, b, ecosystem)))
                    .ToList();

                var status = ClassifyVersion(state, matchedExclusion != null);

                versionPoints.Add(new SpectrumVersionPoint(
                    dep.Version,
                    status,
                    withinFocused,
                    withinAnyApproval,
                    state.Authorization.RuleId,
                    state.MatchedBlockRule?.Id,
                    matchedExclusion?.Id,
                    matchedExclusion?.Vulnerability?.SourceId,
                    state.BlockingAdvisories,
                    state.AcceptedVulnerabilities,
                    fixVersions,
                    state.NeedsVerification,
                    state.CanAdmit && state.NeedsVerification,
                    state.SourcePermitted,
                    state.Authorization.Reason,
                    state.Admission.Reason,
                    item.Uses));
            }
        }

        var evaluatedAt = relationship?.Versions
            .Select(v => v.State?.EvaluatedAtUtc)
            .Where(d => d.HasValue)
            .Select(d => d!.Value)
            .DefaultIfEmpty(nowUtc)
            .Max() ?? nowUtc;
        var auditAt = relationship?.Versions
            .Select(v => v.State?.VulnerabilityDataAtUtc)
            .Where(d => d.HasValue)
            .Select(d => d!.Value)
            .Cast<DateTime?>()
            .Max();

        return new RuleVersionSpectrumViewModel
        {
            Ecosystem = ecosystem,
            PackageName = packageName,
            Source = source,
            FocusedRuleId = focusedRule?.Id,
            Approvals = approvalBands,
            Blocks = matchingBlocks,
            Exclusions = exclusionBands,
            Advisories = advisoryBands,
            RiskAcceptances = riskAcceptanceBands,
            Versions = versionPoints,
            ObservedVersionCount = relationship?.ObservedVersionCount ?? 0,
            ProductionReports = relationship?.ProductionReports ?? true,
            EvaluatedAtUtc = evaluatedAt,
            VulnerabilityDataAtUtc = auditAt
        };
    }

    public static SpectrumIntervalLabel FormatInterval(OsvVersionInterval interval)
    {
        var fixedVersion = interval.EndKind == "fixed" && !string.IsNullOrWhiteSpace(interval.End)
            ? interval.End
            : null;
        var endOp = interval.EndKind == "last_affected" ? "<=" : "<";

        var display = (interval.Introduced, interval.End) switch
        {
            (null, null) => "All versions (*)",
            ({ } start, null) => $">= {start}",
            (null, { } end) => $"{endOp} {end}",
            ({ } start, { } end) => $">= {start}, {endOp} {end}"
        };

        return new SpectrumIntervalLabel(display, fixedVersion);
    }

    public static bool BlockOverlapsApproval(PackageRule block, PackageRule approval)
    {
        if (block.Kind != RuleKind.Block || block.Status != RuleStatus.Approved) return false;
        if (block.Ecosystem != approval.Ecosystem || approval.IsLegacyTemplate) return false;
        if (!TrustPattern.Matches(block.PackagePattern, approval.PackagePattern, approval.Ecosystem)) return false;

        if (block.Version == "*" || approval.Version == "*") return true;

        var blockWild = block.Version.EndsWith(".*", StringComparison.Ordinal);
        var approvalWild = approval.Version.EndsWith(".*", StringComparison.Ordinal);

        if (!blockWild && !approvalWild)
            return TrustPattern.VersionMatches(block.Version, approval.Version, approval.Ecosystem, includePrerelease: true);

        if (blockWild && !approvalWild)
            return TrustPattern.VersionMatches(block.Version, approval.Version, approval.Ecosystem, includePrerelease: true);

        if (!blockWild && approvalWild)
            return TrustPattern.VersionMatches(approval.Version, block.Version, approval.Ecosystem, approval.IncludePrerelease);

        var blockPrefix = block.Version[..^2];
        var approvalPrefix = approval.Version[..^2];
        return string.Equals(blockPrefix, approvalPrefix, StringComparison.Ordinal) ||
               blockPrefix.StartsWith(approvalPrefix + ".", StringComparison.Ordinal) ||
               approvalPrefix.StartsWith(blockPrefix + ".", StringComparison.Ordinal);
    }

    public static Dictionary<int, RuleListSpectrumSignal> BuildRuleListSignals(
        IReadOnlyCollection<PackageRule> rules,
        IReadOnlyCollection<PackageRule> blocks,
        IReadOnlyDictionary<int, int> exclusionCounts,
        IReadOnlyCollection<Entities.Vulnerability> activeAdvisories,
        DateTime nowUtc)
    {
        var byPackage = activeAdvisories
            .Where(v => !v.Withdrawn)
            .GroupBy(v => (v.Ecosystem, Key: NormalizePackageKey(v.Ecosystem, v.PackageName)))
            .ToDictionary(g => g.Key, g => g.ToList());

        var result = new Dictionary<int, RuleListSpectrumSignal>();
        foreach (var rule in rules)
        {
            var matchedBlock = blocks.FirstOrDefault(b => BlockOverlapsApproval(b, rule));
            var blockReason = matchedBlock == null
                ? null
                : $"{matchedBlock.PackagePattern} @ {matchedBlock.Version}: {matchedBlock.Justification}";

            var overlapping = 0;
            var unparsed = 0;
            if (!rule.IsLegacyTemplate &&
                byPackage.TryGetValue((rule.Ecosystem, NormalizePackageKey(rule.Ecosystem, rule.PackagePattern)), out var pkgAdvisories))
            {
                foreach (var advisory in pkgAdvisories)
                {
                    var risk = SafeIntersects(advisory.RawAffectedJson, rule.Ecosystem,
                        advisory.PackageName, rule.Version, rule.IncludePrerelease);
                    if (risk == RangeRisk.Affected) overlapping++;
                    else if (risk == RangeRisk.Unknown) unparsed++;
                }
            }

            var exclusions = exclusionCounts.GetValueOrDefault(rule.Id);
            var expiringSoon = rule.ExpiresAtUtc is { } exp && exp > nowUtc && exp <= nowUtc.AddDays(14);

            result[rule.Id] = new RuleListSpectrumSignal(
                matchedBlock != null,
                blockReason,
                overlapping,
                unparsed,
                exclusions,
                expiringSoon);
        }

        return result;
    }

    public static RangeRisk SafeIntersects(string? affectedJson, string ecosystem, string packageName,
        string versionPattern, bool includePrerelease = false)
    {
        if (string.IsNullOrWhiteSpace(affectedJson)) return RangeRisk.Unknown;
        try
        {
            return OsvRangeMatcher.Intersects(affectedJson, ecosystem, packageName, versionPattern, includePrerelease);
        }
        catch (JsonException)
        {
            return RangeRisk.Unknown;
        }
    }

    private static VersionSpectrumStatus ClassifyVersion(PackageVersionState state, bool matchedExclusion)
    {
        if (state.Blocked) return VersionSpectrumStatus.Blocklisted;
        if (matchedExclusion) return VersionSpectrumStatus.Excluded;
        if (state.BlockingAdvisories.Count > 0) return VersionSpectrumStatus.Vulnerable;
        if (state.AcceptedVulnerabilities.Count > 0 && state.CanAdmit) return VersionSpectrumStatus.RiskAccepted;
        if (!state.Authorized) return VersionSpectrumStatus.OutsideRule;
        if (state.NeedsVerification || !state.CanAdmit) return VersionSpectrumStatus.NeedsVerification;
        return VersionSpectrumStatus.Admitted;
    }

    private static bool IsActiveApproval(PackageRule rule, DateTime nowUtc) =>
        rule.Kind == RuleKind.Approval && rule.Status == RuleStatus.Approved && !rule.IsLegacyTemplate &&
        (rule.ExpiresAtUtc == null || rule.ExpiresAtUtc > nowUtc);

    private static string NormalizePackageKey(string ecosystem, string name) =>
        ecosystem == "nuget" ? name.ToLowerInvariant() : name;
}
