using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services;

/// <summary>Explains the existing admission decision without changing policy or recording a download.</summary>
public class PackageStatusService(TemplateDbContext db, TrustService trust, IConfiguration configuration) : IScopedDependency
{
    public Task<List<PackageVersionState>> DescribeAsync(IEnumerable<Dependency> dependencies)
    {
        var requested = dependencies.ToList();
        return VulnerabilityAuditSnapshot.ReadAsync(db, () => DescribeSnapshotAsync(requested));
    }

    private async Task<List<PackageVersionState>> DescribeSnapshotAsync(List<Dependency> requested)
    {
        if (requested.Count == 0) return [];
        var decisions = await trust.AssessAsync(requested);
        var rules = await db.Rules.AsNoTracking().Where(r => r.Kind == RuleKind.Approval &&
            r.Status != RuleStatus.Pending).ToListAsync();
        var blocks = await db.Rules.AsNoTracking().Where(r => r.Kind == RuleKind.Block &&
            r.Status == RuleStatus.Approved).ToListAsync();
        var exclusions = await db.Rules.AsNoTracking().Where(r => r.Kind == RuleKind.VulnerabilityExclusion)
            .Include(r => r.Vulnerability).ToListAsync();
        var nugetNames = requested.Where(d => d.Ecosystem == "nuget").Select(d => d.Name.ToLowerInvariant()).Distinct().ToList();
        var npmNames = requested.Where(d => d.Ecosystem == "npm").Select(d => d.Name).Distinct().ToList();
        var advisories = await db.Vulnerabilities.AsNoTracking().Where(v => !v.Withdrawn &&
                (v.Ecosystem == "nuget" && nugetNames.Contains(v.PackageName.ToLower()) ||
                 v.Ecosystem == "npm" && npmNames.Contains(v.PackageName) ||
                 v.Matches.Any(m => m.Active && (m.PackageVersion.Ecosystem == "nuget" && nugetNames.Contains(m.PackageVersion.Name.ToLower()) ||
                     m.PackageVersion.Ecosystem == "npm" && npmNames.Contains(m.PackageVersion.Name)))))
            .Include(v => v.Matches.Where(m => m.Active)).ThenInclude(m => m.PackageVersion)
            .AsSplitQuery().ToListAsync();
        var audit = await db.VulnerabilitySyncStates.AsNoTracking().FirstOrDefaultAsync();
        var now = DateTime.UtcNow;
        var auditUncertain = audit?.LastSuccessAtUtc == null || audit.LastSuccessAtUtc <= now.AddHours(-12) ||
            audit.LastSuccessAtUtc > now || VulnerabilityAuditFreshness.HasFailedLatestAttempt(
                audit.LastAttemptAtUtc, audit.LastSuccessAtUtc, audit.LastError);
        return requested.Select((dependency, index) =>
        {
            var comparison = dependency.Ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var matchingAdvisories = advisories.Select(v => new
            {
                Advisory = v,
                Recorded = v.Matches.Any(m => m.PackageVersion.Version == dependency.Version &&
                    m.PackageVersion.Ecosystem == dependency.Ecosystem && m.PackageVersion.Name.Equals(dependency.Name, comparison))
            }).Where(v => v.Recorded || v.Advisory.Ecosystem == dependency.Ecosystem &&
                v.Advisory.PackageName.Equals(dependency.Name, comparison)).Select(v => new
            {
                v.Advisory, v.Recorded,
                Risk = v.Recorded ? RangeRisk.Affected : OsvRangeMatcher.Intersects(v.Advisory.RawAffectedJson,
                    dependency.Ecosystem, dependency.Name, dependency.Version)
            }).ToList();
            return new PackageVersionState
            {
                Dependency = dependency,
                Authorization = TrustService.Evaluate(dependency, rules, blocks, now, exclusions),
                Admission = decisions[index],
                SourcePermitted = AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source),
                AuditDataUncertain = auditUncertain,
                VulnerabilityRangeUnknown = matchingAdvisories.Any(v => !v.Recorded && v.Risk == RangeRisk.Unknown),
                Advisories = matchingAdvisories.Where(v => v.Recorded || v.Risk == RangeRisk.Affected)
                    .Select(v => v.Advisory).ToList(),
                Rules = rules.Where(r => r.Ecosystem == dependency.Ecosystem &&
                    r.Source == TrustPattern.NormalizeSource(dependency.Source) && r.MatchesPackage(dependency.Name)).ToList(),
                EvaluatedAtUtc = now,
                VulnerabilityDataAtUtc = audit?.LastSuccessAtUtc
            };
        }).ToList();
    }
}
