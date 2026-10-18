using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Services;

public class TrustService(TemplateDbContext db) : IScopedDependency
{
    public async Task<List<DependencyDecision>> AssessAsync(IEnumerable<Dependency> dependencies) =>
        (await AssessCoreAsync(dependencies)).Decisions;

    public async Task<List<DependencyDecision>> CheckAsync(IEnumerable<Dependency> dependencies)
    {
        var assessment = await AssessCoreAsync(dependencies);
        var decisions = assessment.Decisions;
        var now = DateTime.UtcNow;
        var existingIds = decisions.Where(d => d.Trusted).Select(d => d.Dependency)
            .Concat(assessment.PendingExisting)
            .Select(dependency =>
            {
                var identity = Identity(dependency.Ecosystem, dependency.Name, dependency.Version,
                    TrustPattern.NormalizeSource(dependency.Source));
                return assessment.Known[identity].Single(artifact =>
                    artifact.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase)).Id;
            }).Distinct().ToList();
        foreach (var ids in existingIds.Chunk(500))
        {
            var artifacts = await db.PackageArtifacts.Where(a => ids.Contains(a.Id)).ToListAsync();
            foreach (var artifact in artifacts) artifact.FirstTrustedAtUtc ??= now;
        }
        foreach (var dependency in assessment.NewlyAdmitted)
        {
            var source = TrustPattern.NormalizeSource(dependency.Source);
            var identity = Identity(dependency.Ecosystem, dependency.Name, dependency.Version, source);
            if (assessment.Known[identity].Any(a => a.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase)) ||
                db.PackageArtifacts.Local.Any(a => Identity(a.Ecosystem, a.Name, a.Version, a.Source) == identity &&
                    a.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase))) continue;
            db.PackageArtifacts.Add(new PackageArtifact
            {
                Ecosystem = dependency.Ecosystem, Name = dependency.Name, Version = dependency.Version,
                Source = source, Sha256 = dependency.Sha256.ToLowerInvariant()
            });
        }
        await db.SaveChangesAsync();
        return decisions;
    }

    private Task<Assessment> AssessCoreAsync(IEnumerable<Dependency> dependencies)
    {
        var requested = dependencies.ToList();
        return VulnerabilityAuditSnapshot.ExecuteAsync(db, () => AssessSnapshotAsync(requested));
    }

    private async Task<Assessment> AssessSnapshotAsync(IReadOnlyCollection<Dependency> requested)
    {
        var conflicting = requested.GroupBy(d => Identity(d.Ecosystem, d.Name, d.Version, TrustPattern.NormalizeSource(d.Source)))
            .Where(g => g.Select(d => d.Sha256.ToLowerInvariant()).Distinct().Skip(1).Any())
            .Select(g => g.Key).ToHashSet();
        var rules = await db.TrustRules.AsNoTracking().Where(r => r.Status != TrustRuleStatus.Pending).ToListAsync();
        var blocks = await db.BlockRules.AsNoTracking().Where(r => r.Active).ToListAsync();
        var artifacts = await LoadMatchingArtifactsAsync(requested);
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking()
            .Include(e => e.Vulnerability).ToListAsync();
        var known = artifacts.ToLookup(a => Identity(a.Ecosystem, a.Name, a.Version, a.Source));
        var conflictingVerified = ConflictingVerifiedIdentities(artifacts);
        var affectedIds = new HashSet<int>();
        foreach (var ids in artifacts.Select(a => a.Id).Chunk(500))
        {
            var affected = await db.VulnerabilityMatches.AsNoTracking()
                .Where(m => ids.Contains(m.PackageArtifactId) && m.Active &&
                    !m.Vulnerability.Withdrawn)
                .Select(m => m.PackageArtifactId).ToListAsync();
            affectedIds.UnionWith(affected);
        }
        var now = DateTime.UtcNow;
        var audit = await db.VulnerabilitySyncStates.AsNoTracking()
            .Select(s => new { s.LastSuccessfulAttemptAtUtc, s.LastSuccessAtUtc }).FirstOrDefaultAsync();
        var newlyAdmitted = new List<Dependency>();
        var pendingExisting = new List<Dependency>();
        var decisions = requested.Select(dependency =>
        {
            var identity = Identity(dependency.Ecosystem, dependency.Name, dependency.Version,
                TrustPattern.NormalizeSource(dependency.Source));
            if (conflicting.Contains(identity)) return Reject(dependency, "The same package identity has conflicting hashes in this build.");
            var decision = Evaluate(dependency, rules, blocks, now, exclusions);
            if (!decision.Trusted) return decision;
            var matchingArtifacts = known[Identity(dependency.Ecosystem, dependency.Name, dependency.Version,
                TrustPattern.NormalizeSource(dependency.Source))].ToList();
            var trustedArtifacts = matchingArtifacts.Where(a => a.FirstTrustedAtUtc != null).ToList();
            if (conflictingVerified.Contains(identity))
                return Reject(dependency, "Conflicting previously verified package hashes; manual review required.");
            if (trustedArtifacts.Count > 0 && !trustedArtifacts.Any(a => a.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase)))
                return Reject(dependency, "Previously recorded package bytes changed.");
            var sameHash = matchingArtifacts.Where(a => a.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase)).ToList();
            if (sameHash.Count == 0)
            {
                newlyAdmitted.Add(dependency);
                return Reject(dependency, "Package archive verification and vulnerability audit are pending.");
            }
            if (sameHash.All(a => a.SourceVerifiedAtUtc == null))
                return Reject(dependency, "Package archive has not been independently verified from its source.");
            if (sameHash.All(a => !VulnerabilityAuditFreshness.IsCurrent(a.LastCheckedAtUtc,
                    audit?.LastSuccessfulAttemptAtUtc, audit?.LastSuccessAtUtc, now)))
            {
                pendingExisting.Add(dependency);
                return Reject(dependency, "Vulnerability audit has not completed for this package within 12 hours.");
            }
            if (matchingArtifacts.Any(a => a.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase) &&
                                          affectedIds.Contains(a.Id)))
                return Reject(dependency, "This version has a known active vulnerability.");
            return decision;
        }).ToList();
        return new Assessment(decisions, newlyAdmitted, pendingExisting, known);
    }

    private sealed record Assessment(List<DependencyDecision> Decisions, List<Dependency> NewlyAdmitted,
        List<Dependency> PendingExisting, ILookup<string, PackageArtifact> Known);

    private async Task<List<PackageArtifact>> LoadMatchingArtifactsAsync(IReadOnlyCollection<Dependency> requested)
    {
        var identities = requested.Select(d => Identity(d.Ecosystem, d.Name, d.Version,
            TrustPattern.NormalizeSource(d.Source))).ToHashSet(StringComparer.Ordinal);
        var result = new List<PackageArtifact>();
        foreach (var ecosystem in requested.GroupBy(d => d.Ecosystem))
        foreach (var names in ecosystem.Select(d => ecosystem.Key == "nuget" ? d.Name.ToLowerInvariant() : d.Name)
                     .Distinct(StringComparer.Ordinal).Chunk(250))
        {
            var versions = ecosystem.Where(d => names.Contains(ecosystem.Key == "nuget"
                    ? d.Name.ToLowerInvariant() : d.Name))
                .Select(d => d.Version).Distinct(StringComparer.Ordinal).ToArray();
            var candidates = ecosystem.Key == "nuget"
                ? await db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == "nuget" &&
                    names.Contains(a.Name.ToLower()) && versions.Contains(a.Version)).ToListAsync()
                : await db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == "npm" &&
                    names.Contains(a.Name) && versions.Contains(a.Version)).ToListAsync();
            result.AddRange(candidates.Where(a => identities.Contains(Identity(a.Ecosystem,
                a.Name, a.Version, a.Source))));
        }
        return result;
    }

    internal static string Identity(string ecosystem, string name, string version, string source) =>
        $"{ecosystem}\n{(ecosystem == "nuget" ? name.ToLowerInvariant() : name)}\n{version}\n{source}";

    internal static HashSet<string> ConflictingVerifiedIdentities(IEnumerable<PackageArtifact> artifacts) =>
        artifacts.Where(a => a.SourceVerifiedAtUtc != null || a.FirstTrustedAtUtc != null)
            .GroupBy(a => Identity(a.Ecosystem, a.Name, a.Version, a.Source))
            .Where(group => group.Select(a => a.Sha256).Distinct(StringComparer.OrdinalIgnoreCase).Skip(1).Any())
            .Select(group => group.Key).ToHashSet();

    private static DependencyDecision Reject(Dependency dependency, string reason) =>
        new() { Dependency = dependency, Trusted = false, Reason = reason };

    public static DependencyDecision Evaluate(Dependency dependency, IEnumerable<TrustRule> rules,
        IEnumerable<BlockRule> blocks, DateTime now,
        IReadOnlyCollection<TrustRuleVulnerabilityExclusion>? exclusions = null)
    {
        var source = TrustPattern.NormalizeSource(dependency.Source);
        var block = BlockRulePolicy.Match(blocks, dependency.Ecosystem, dependency.Name, dependency.Version);
        if (block != null)
            return Decision(false, BlockRulePolicy.Explain(block, dependency.Name, dependency.Version), null);
        var matching = rules.Where(r => r.Ecosystem == dependency.Ecosystem && r.Source == source &&
            TrustPattern.Matches(r.PackagePattern, dependency.Name, dependency.Ecosystem) &&
            TrustPattern.VersionMatches(r.Version, dependency.Version, dependency.Ecosystem, r.IncludePrerelease)).ToList();
        var denied = matching.FirstOrDefault(r => r.Status is TrustRuleStatus.Rejected or TrustRuleStatus.Revoked);
        if (denied != null) return Decision(false, "Explicitly rejected or revoked.", denied);

        var approved = matching.Where(r => r.Status == TrustRuleStatus.Approved).ToList();
        // An explicit version exclusion must not be bypassed by another
        // overlapping approval, including a more specific pinned rule.
        var excluded = approved.Where(r => r.ExpiresAtUtc == null || r.ExpiresAtUtc > now)
            .Select(r => MatchingExclusion(r, dependency, exclusions))
            .FirstOrDefault(e => e != null);
        if (excluded != null)
            return Decision(false, $"Excluded vulnerable or uncertain version: {excluded.Vulnerability.SourceId}.", null);
        // A pinned approval cannot be bypassed by a wider wildcard rule.
        var pinned = approved.Where(r => r.Sha256 != null && r.Version == dependency.Version &&
            r.PackagePattern.Equals(dependency.Name, dependency.Ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)).ToList();
        if (pinned.Count > 0 && !pinned.Any(r => string.Equals(r.Sha256, dependency.Sha256, StringComparison.OrdinalIgnoreCase)))
            return Decision(false, "SHA-256 does not match the pinned approval.", pinned[0]);

        var candidates = pinned.Count > 0 ? pinned : approved;
        var eligible = candidates.Where(r => (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
            (r.Sha256 == null || r.Sha256.Equals(dependency.Sha256, StringComparison.OrdinalIgnoreCase))).ToList();
        var allowed = eligible.FirstOrDefault();
        return allowed == null
            ? Decision(false, candidates.Count > 0 ? "Approval expired; review required." : "No approved trust rule.", null)
            : Decision(true, allowed.Sha256 == null ? "Approved by an unpinned trust rule." : "Approved SHA-256.", allowed);

        DependencyDecision Decision(bool trusted, string reason, TrustRule? rule) => new()
        {
            Dependency = dependency, Trusted = trusted, Reason = reason, RuleId = rule?.Id
        };
    }

    internal static TrustRuleVulnerabilityExclusion? MatchingExclusion(TrustRule rule, Dependency dependency,
        IReadOnlyCollection<TrustRuleVulnerabilityExclusion>? exclusions) => exclusions?.FirstOrDefault(e =>
        e.TrustRuleId == rule.Id && e.Vulnerability is { Withdrawn: false } &&
        e.Vulnerability.Ecosystem == dependency.Ecosystem &&
        e.Vulnerability.PackageName.Equals(dependency.Name,
            dependency.Ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) &&
        OsvRangeMatcher.Intersects(e.Vulnerability.RawAffectedJson, dependency.Ecosystem,
            dependency.Name, dependency.Version) != RangeRisk.NotAffected);
}
