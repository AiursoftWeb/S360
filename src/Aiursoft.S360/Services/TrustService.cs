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

    public async Task<List<DependencyDecision>> AssessAsync(IEnumerable<Dependency> dependencies)
    {
        var requested = dependencies.ToList();
        if (requested.Count == 0) return [];
        var result = await VulnerabilityAuditSnapshot.ReadAsync(db, () => AssessSnapshotAsync(requested, includeDetails: false));
        return result.Decisions;
    }

    internal Task<TrustAssessment> AssessForDisplayAsync(IReadOnlyList<Dependency> requested) => requested.Count == 0
        ? Task.FromResult(new TrustAssessment([], [], [], [], null, DateTime.UtcNow))
        : VulnerabilityAuditSnapshot.ReadAsync(db, () => AssessSnapshotAsync(requested, includeDetails: true));

    private async Task<TrustAssessment> AssessSnapshotAsync(IReadOnlyList<Dependency> requested, bool includeDetails)
    {
        var scope = new PolicyPackageNames(requested.Select(d => (d.Ecosystem, d.Name)));
        var nuget = scope.NuGet;
        var npm = scope.Npm;
        var packageRules = db.Rules.AsNoTracking().Where(r =>
            (r.Ecosystem == "nuget" && nuget.Length > 0 &&
             (nuget.Contains(r.PackagePattern.ToLower()) || r.PackagePattern.Contains("*"))) ||
            (r.Ecosystem == "npm" && npm.Length > 0 &&
             (npm.Contains(r.PackagePattern) || r.PackagePattern.Contains("*"))));
        var approvalQuery = packageRules.Where(r => r.Kind == RuleKind.Approval && r.Status != RuleStatus.Pending);
        var rules = await (includeDetails ? approvalQuery : approvalQuery.Select(r => new PackageRule
        {
            Id = r.Id, Status = r.Status, Ecosystem = r.Ecosystem, PackagePattern = r.PackagePattern,
            Version = r.Version, Source = r.Source, IncludePrerelease = r.IncludePrerelease,
            ApplicationId = r.ApplicationId, RequestedAtUtc = r.RequestedAtUtc, ExpiresAtUtc = r.ExpiresAtUtc
        })).ToListAsync();
        var blocks = await packageRules.Where(r => r.Kind == RuleKind.Block && r.Status == RuleStatus.Approved).ToListAsync();
        var approvedIds = rules.Where(r => r.Status == RuleStatus.Approved).Select(r => r.Id).ToArray();
        var exclusions = approvedIds.Length == 0 ? [] : await db.Rules.AsNoTracking()
            .Where(r => r.Kind == RuleKind.VulnerabilityExclusion && r.ParentRuleId.HasValue &&
                approvedIds.Contains(r.ParentRuleId.Value)).Include(r => r.Vulnerability).ToListAsync();
        var now = DateTime.UtcNow;
        var authorization = requested.Select(d => Evaluate(d, rules, blocks, now, exclusions)).ToList();
        var targets = includeDetails ? requested : requested.Where((_, index) => authorization[index].Trusted).ToList();
        if (targets.Count == 0) return new TrustAssessment(authorization, authorization, [], rules, null, now);

        var vulnerabilities = await VulnerabilityPolicy.LoadAsync(db, now, targets, includeDetails);
        var details = includeDetails ? requested.Select(vulnerabilities.Assess).ToList() : [];
        var audit = await db.VulnerabilitySyncStates.AsNoTracking().FirstOrDefaultAsync();
        var approvals = await db.RuleChanges.AsNoTracking()
            .Where(r => r.Decision == RuleStatus.Approved && approvedIds.Contains(r.RuleId))
            .GroupBy(r => r.RuleId).Select(g => new { Id = g.Key, At = g.Max(r => r.ReviewedAtUtc) })
            .ToDictionaryAsync(r => r.Id, r => r.At);
        var fresh = audit?.LastSuccessAtUtc > now.AddHours(-12) && audit.LastSuccessAtUtc <= now;
        var reviewedVersions = fresh && audit?.LastSuccessfulAttemptAtUtc is { } auditStarted
            ? await LoadReviewedVersionsAsync(rules, approvals, scope, auditStarted, audit.LastSuccessAtUtc, now)
            : [];
        var decisions = requested.Select((dependency, index) =>
        {
            var decision = authorization[index];
            if (!decision.Trusted) return decision;
            var assessment = includeDetails ? details[index] : vulnerabilities.Assess(dependency);
            if (assessment.Blocking.Count > 0)
                return new DependencyDecision { Dependency = dependency,
                    Reason = $"This version has a known active vulnerability: {assessment.Blocking[0].SourceId}." };
            // A package-level audit covers new versions. An approval from a dependency report
            // can also reuse the current audit for the exact version in that report.
            var covered = rules.Any(r => r.Status == RuleStatus.Approved && r.Ecosystem == dependency.Ecosystem &&
                r.MatchesPackage(dependency.Name) && !r.IsLegacyTemplate &&
                (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
                r.RequestedAtUtc <= audit?.LastSuccessfulAttemptAtUtc &&
                (!approvals.TryGetValue(r.Id, out var at) || at <= audit.LastSuccessfulAttemptAtUtc)) ||
                (reviewedVersions.Count > 0 && reviewedVersions.Contains(Identity(dependency.Ecosystem,
                    dependency.Name, dependency.Version, TrustPattern.NormalizeSource(dependency.Source))));
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
        return new TrustAssessment(authorization, decisions, details, rules, audit, now);
    }

    private async Task<HashSet<string>> LoadReviewedVersionsAsync(IEnumerable<PackageRule> rules,
        Dictionary<int, DateTime> approvals, PolicyPackageNames scope, DateTime auditStarted, DateTime? auditCompleted,
        DateTime now)
    {
        var recentlyApproved = rules.Where(r => r.ApplicationId.HasValue && r.Status == RuleStatus.Approved &&
                !r.IsLegacyTemplate && !r.Version.Contains('*') && (r.ExpiresAtUtc == null || r.ExpiresAtUtc > now) &&
                approvals.TryGetValue(r.Id, out var reviewedAt) && reviewedAt <= now &&
                (reviewedAt > auditStarted || r.RequestedAtUtc > auditStarted))
            .Select(r => (ApplicationId: r.ApplicationId!.Value,
                Identity: Identity(r.Ecosystem, r.PackagePattern, r.Version, r.Source)))
            .ToHashSet();
        if (recentlyApproved.Count == 0) return [];

        var applicationIds = recentlyApproved.Select(r => r.ApplicationId).Distinct().ToArray();
        var nuget = scope.NuGet;
        var npm = scope.Npm;
        var versions = await db.ApplicationPackages.AsNoTracking()
            .Where(p => applicationIds.Contains(p.ApplicationId) && p.Application.Status == ApplicationStatus.Approved &&
                ((p.PackageVersion.Ecosystem == "nuget" && nuget.Contains(p.PackageVersion.Name.ToLower())) ||
                 (p.PackageVersion.Ecosystem == "npm" && npm.Contains(p.PackageVersion.Name))))
            .Select(p => new
            {
                p.ApplicationId, p.PackageVersion.Ecosystem, p.PackageVersion.Name,
                p.PackageVersion.Version, p.PackageVersion.Source, p.PackageVersion.LastCheckedAtUtc
            }).ToListAsync();
        return versions.Where(v => VulnerabilityAuditFreshness.IsCurrent(v.LastCheckedAtUtc, auditStarted, auditCompleted, now))
            .Select(v => (v.ApplicationId, Identity: Identity(v.Ecosystem, v.Name, v.Version, v.Source)))
            .Where(recentlyApproved.Contains)
            .Select(v => v.Identity)
            .ToHashSet(StringComparer.Ordinal);
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

internal sealed record TrustAssessment(List<DependencyDecision> Authorization, List<DependencyDecision> Decisions,
    List<VulnerabilityAssessment> Vulnerabilities, List<PackageRule> Rules, VulnerabilitySyncState? Audit, DateTime EvaluatedAtUtc);
