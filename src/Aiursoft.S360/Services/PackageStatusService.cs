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
        var audit = await db.VulnerabilitySyncStates.AsNoTracking().FirstOrDefaultAsync();
        var now = DateTime.UtcNow;
        var auditUncertain = audit?.LastSuccessAtUtc == null || audit.LastSuccessAtUtc <= now.AddHours(-12) ||
            audit.LastSuccessAtUtc > now || VulnerabilityAuditFreshness.HasFailedLatestAttempt(
                audit.LastAttemptAtUtc, audit.LastSuccessAtUtc, audit.LastError);
        var vulnerabilities = await VulnerabilityPolicy.LoadAsync(db, now);
        return requested.Select((dependency, index) =>
        {
            var assessment = vulnerabilities.Assess(dependency);
            return new PackageVersionState
            {
                Dependency = dependency,
                Authorization = TrustService.Evaluate(dependency, rules, blocks, now, exclusions),
                Admission = decisions[index],
                SourcePermitted = AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source),
                AuditDataUncertain = auditUncertain,
                VulnerabilityRangeUnknown = assessment.RangeUnknown,
                Advisories = assessment.Findings,
                BlockingAdvisories = assessment.Blocking.Where(assessment.Findings.Contains).ToList(),
                AcceptedVulnerabilities = assessment.Accepted,
                Rules = rules.Where(r => r.Ecosystem == dependency.Ecosystem &&
                    r.Source == TrustPattern.NormalizeSource(dependency.Source) && r.MatchesPackage(dependency.Name)).ToList(),
                EvaluatedAtUtc = now,
                VulnerabilityDataAtUtc = audit?.LastSuccessAtUtc
            };
        }).ToList();
    }
}
