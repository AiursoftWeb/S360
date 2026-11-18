using Aiursoft.Scanner.Abstractions;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Microsoft.EntityFrameworkCore;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Services;

/// <summary>Evaluates authorization and known vulnerability ranges. Package bytes are the registry's responsibility.</summary>
public class TrustService(TemplateDbContext db) : IScopedDependency
{
    internal static string Identity(string ecosystem, string name, string version, string source) =>
        $"{ecosystem}\n{(ecosystem == "nuget" ? name.ToLowerInvariant() : name)}\n{version}\n{source}";

    public static bool IsValidPackageName(string ecosystem, string name) =>
        ecosystem is "nuget" or "npm" && TrustPattern.IsValid(name) && !name.Contains('*') &&
        name is not ("." or "..") && (ecosystem != "nuget" || !name.Contains('/'));

    public async Task<List<MirrorCandidateDecision>> EvaluateCandidatesAsync(IReadOnlyList<MirrorCandidate> candidates)
    {
        var decisions = await AssessAsync(candidates.Select(c => new Dependency
        {
            Ecosystem = c.Ecosystem,
            Name = c.Name,
            Version = c.Version,
            Source = c.Source
        }));
        return decisions.Select((d, i) => new MirrorCandidateDecision(candidates[i], d.Trusted)).ToList();
    }

    public Task<List<DependencyDecision>> CheckAsync(IEnumerable<Dependency> dependencies) => AssessAsync(dependencies);

    public Task<List<DependencyDecision>> ReviewAsync(IEnumerable<Dependency> dependencies) =>
        AssessAsync(dependencies);

    public Task<List<DependencyDecision>> AssessAsync(IEnumerable<Dependency> dependencies)
    {
        var requested = dependencies.ToList();
        return VulnerabilityAuditSnapshot.ReadAsync(db, () => AssessSnapshotAsync(requested));
    }

    private async Task<List<DependencyDecision>> AssessSnapshotAsync(IReadOnlyCollection<Dependency> requested)
    {
        var rules = await db.Rules.Where(r => r.Kind == RuleKind.Approval).AsNoTracking()
            .Where(r => r.Status != RuleStatus.Pending).ToListAsync();
        var blocks = await db.Rules.Where(r => r.Kind == RuleKind.Block).AsNoTracking().Where(r => r.Status == RuleStatus.Approved).ToListAsync();
        var exclusions = await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var now = DateTime.UtcNow;
        var vulnerabilities = await VulnerabilityPolicy.LoadAsync(db, now);
        var audit = await db.VulnerabilitySyncStates.AsNoTracking().FirstOrDefaultAsync();
        var approvals = await db.RuleChanges.AsNoTracking()
            .Where(r => r.Decision == RuleStatus.Approved)
            .GroupBy(r => r.RuleId).Select(g => new { Id = g.Key, At = g.Max(r => r.ReviewedAtUtc) })
            .ToDictionaryAsync(r => r.Id, r => r.At);
        var fresh = audit?.LastSuccessAtUtc > now.AddHours(-12) && audit.LastSuccessAtUtc <= now;
        return requested.Select(dependency =>
        {
            var decision = Evaluate(dependency, rules, blocks, now, exclusions);
            if (!decision.Trusted) return decision;
            var assessment = vulnerabilities.Assess(dependency);
            if (assessment.Blocking.Count > 0)
                return new DependencyDecision { Dependency = dependency,
                    Reason = $"This version has a known active vulnerability: {assessment.Blocking[0].SourceId}." };
            // A successful package-level OSV query covers new versions too. Newly approved
            // package names must enter the next audit before absence of findings means clean.
            var covered = rules.Any(r => r.Status == RuleStatus.Approved && r.Ecosystem == dependency.Ecosystem &&
                r.MatchesPackage(dependency.Name) && !r.IsLegacyTemplate &&
                (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
                r.RequestedAtUtc <= audit?.LastSuccessfulAttemptAtUtc &&
                (!approvals.TryGetValue(r.Id, out var at) || at <= audit.LastSuccessfulAttemptAtUtc));
            if (fresh && covered && assessment.Accepted.Count > 0)
                return new DependencyDecision { Dependency = dependency, Trusted = true, RuleId = decision.RuleId,
                    Reason = "Approved by package policy; known vulnerability risk accepted by rules: " +
                        string.Join(", ", assessment.Accepted.Select(a => a.Rule.Id).Distinct()) + "." };
            return fresh && covered ? decision : new DependencyDecision
            {
                Dependency = dependency,
                PendingVerification = true,
                Reason = "Current vulnerability data is unavailable for this package. A vulnerability refresh is required."
            };
        }).ToList();
    }

    public static DependencyDecision Evaluate(Dependency dependency, IEnumerable<PackageRule> rules,
        IEnumerable<PackageRule> blocks, DateTime now,
        IReadOnlyCollection<PackageRule>? exclusions = null)
    {
        var source = TrustPattern.NormalizeSource(dependency.Source);
        var block = BlockRulePolicy.Match(blocks, dependency.Ecosystem, dependency.Name, dependency.Version);
        if (block != null)
            return Decision(false, BlockRulePolicy.Explain(block, dependency.Name, dependency.Version), null);
        var matching = rules.Where(r => r.Ecosystem == dependency.Ecosystem && r.Source == source &&
            r.MatchesPackage(dependency.Name) &&
            TrustPattern.VersionMatches(r.Version, dependency.Version, dependency.Ecosystem, r.IncludePrerelease)).ToList();
        var denied = matching.FirstOrDefault(r => r.Status is RuleStatus.Rejected or RuleStatus.Revoked);
        if (denied != null) return Decision(false, "Explicitly rejected or revoked.", denied);

        var approved = matching.Where(r => r.Status == RuleStatus.Approved).ToList();
        // An explicit version exclusion must not be bypassed by another
        // overlapping approval, including a more specific pinned rule.
        var excluded = approved.Where(r => r.ExpiresAtUtc == null || r.ExpiresAtUtc > now)
            .Select(r => MatchingExclusion(r, dependency, exclusions))
            .FirstOrDefault(e => e != null);
        if (excluded != null)
            return Decision(false, $"Excluded vulnerable or uncertain version: {excluded.Vulnerability!.SourceId}.", null);
        var allowed = approved.FirstOrDefault(r => r.ExpiresAtUtc == null || r.ExpiresAtUtc > now);
        return allowed == null
            ? Decision(false, approved.Count > 0 ? "Approval expired; review required." : "No approved trust rule.", null)
            : Decision(true, "Approved by package policy.", allowed);

        DependencyDecision Decision(bool trusted, string reason, PackageRule? rule) => new()
        {
            Dependency = dependency,
            Trusted = trusted,
            Reason = reason,
            RuleId = rule?.Id
        };
    }

    internal static PackageRule? MatchingExclusion(PackageRule rule, Dependency dependency,
        IReadOnlyCollection<PackageRule>? exclusions) => exclusions?.FirstOrDefault(e =>
        e.ParentRuleId == rule.Id && e.Vulnerability is { Withdrawn: false } &&
        e.Vulnerability.Ecosystem == dependency.Ecosystem &&
        e.Vulnerability.PackageName.Equals(dependency.Name,
            dependency.Ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
        OsvRangeMatcher.Intersects(e.Vulnerability.RawAffectedJson, dependency.Ecosystem,
            dependency.Name, dependency.Version) != RangeRisk.NotAffected);
}
