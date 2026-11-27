using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

// These are independent facts. A version can be both vulnerable and unauthorized.
public class PackageVersionState
{
    public required Dependency Dependency { get; init; }
    public required DependencyDecision Authorization { get; init; }
    public required DependencyDecision Admission { get; init; }
    public bool SourcePermitted { get; init; }
    public bool AuditDataUncertain { get; init; }
    public bool VulnerabilityRangeUnknown { get; init; }
    public List<Vulnerability> Advisories { get; init; } = [];
    public List<Vulnerability> BlockingAdvisories { get; init; } = [];
    public List<AcceptedVulnerability> AcceptedVulnerabilities { get; init; } = [];
    public List<PackageRule> Rules { get; init; } = [];
    public PackageRule? MatchedBlockRule { get; init; }
    public bool Blocked => MatchedBlockRule != null;
    public DateTime EvaluatedAtUtc { get; init; }
    public DateTime? VulnerabilityDataAtUtc { get; init; }
    public bool Authorized => SourcePermitted && Authorization.Trusted;
    public bool CanAdmit => SourcePermitted && Admission.Trusted;
    public bool HasKnownVulnerability => Advisories.Count > 0;
    public bool NeedsVerification => AuditDataUncertain || VulnerabilityRangeUnknown || Admission.PendingVerification;
}

public class PackageRelationshipViewModel
{
    public required string Name { get; init; }
    public required string Ecosystem { get; init; }
    public required string Source { get; init; }
    public List<InventoryVersion> Versions { get; init; } = [];
    public List<Vulnerability> BlockingAdvisories { get; init; } = [];
    public List<AcceptedVulnerability> AcceptedVulnerabilities { get; init; } = [];
    public List<PackageRule> Rules { get; init; } = [];
    public bool ProductionReports { get; init; } = true;
    public bool IncompleteReports { get; init; }
    public int ObservedVersionCount { get; init; }
    public int CompleteReportCount { get; init; }
    public DateTime? OldestReportAtUtc { get; init; }
    public DateTime? LatestReportAtUtc { get; init; }
}
