using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.Scanner.Abstractions;

namespace Aiursoft.S360.Services;

/// <summary>Explains the existing admission decision without changing policy or recording a download.</summary>
public class PackageStatusService(TrustService trust, IConfiguration configuration) : IScopedDependency
{
    public async Task<List<PackageVersionState>> DescribeAsync(IEnumerable<Dependency> dependencies)
    {
        var requested = dependencies.ToList();
        if (requested.Count == 0) return [];
        var result = await trust.AssessForDisplayAsync(requested);
        var audit = result.Audit;
        var now = result.EvaluatedAtUtc;
        var auditUncertain = audit?.LastSuccessAtUtc == null || audit.LastSuccessAtUtc <= now.AddHours(-12) ||
            audit.LastSuccessAtUtc > now || VulnerabilityAuditFreshness.HasFailedLatestAttempt(
                audit.LastAttemptAtUtc, audit.LastSuccessAtUtc, audit.LastError);
        return requested.Select((dependency, index) =>
        {
            var assessment = result.Vulnerabilities[index];
            return new PackageVersionState
            {
                Dependency = dependency,
                Authorization = result.Authorization[index],
                Admission = result.Decisions[index],
                SourcePermitted = AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source),
                AuditDataUncertain = auditUncertain,
                VulnerabilityRangeUnknown = assessment.RangeUnknown,
                Advisories = assessment.Findings,
                BlockingAdvisories = assessment.Blocking.Where(assessment.Findings.Contains).ToList(),
                AcceptedVulnerabilities = assessment.Accepted,
                Rules = result.Rules.Where(r => r.Ecosystem == dependency.Ecosystem &&
                    r.Source == TrustPattern.NormalizeSource(dependency.Source) && r.MatchesPackage(dependency.Name)).ToList(),
                MatchedBlockRule = BlockRulePolicy.Match(result.Blocks, dependency.Ecosystem, dependency.Name, dependency.Version),
                EvaluatedAtUtc = now,
                VulnerabilityDataAtUtc = audit?.LastSuccessAtUtc
            };
        }).ToList();
    }
}
