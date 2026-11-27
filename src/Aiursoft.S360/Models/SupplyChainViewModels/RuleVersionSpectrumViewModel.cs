using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public enum VersionSpectrumStatus
{
    Admitted,
    RiskAccepted,
    Vulnerable,
    Excluded,
    Blocklisted,
    NeedsVerification,
    OutsideRule
}

public class RuleVersionSpectrumViewModel
{
    public required string Ecosystem { get; init; }
    public required string PackageName { get; init; }
    public required string Source { get; init; }
    public int? FocusedRuleId { get; init; }
    public List<SpectrumApprovalBand> Approvals { get; init; } = [];
    public List<SpectrumBlockBand> Blocks { get; init; } = [];
    public List<SpectrumExclusionBand> Exclusions { get; init; } = [];
    public List<SpectrumAdvisoryBand> Advisories { get; init; } = [];
    public List<SpectrumRiskAcceptanceBand> RiskAcceptances { get; init; } = [];
    public List<SpectrumVersionPoint> Versions { get; init; } = [];
    public int ObservedVersionCount { get; init; }
    public bool ProductionReports { get; init; } = true;
    public DateTime EvaluatedAtUtc { get; init; }
    public DateTime? VulnerabilityDataAtUtc { get; init; }

    public int AdmittedCount => Versions.Count(v => v.Status == VersionSpectrumStatus.Admitted);
    public int RiskAcceptedCount => Versions.Count(v => v.Status == VersionSpectrumStatus.RiskAccepted);
    public int VulnerableCount => Versions.Count(v => v.Status == VersionSpectrumStatus.Vulnerable);
    public int ExcludedCount => Versions.Count(v => v.Status == VersionSpectrumStatus.Excluded);
    public int BlocklistedCount => Versions.Count(v => v.Status == VersionSpectrumStatus.Blocklisted);
    public int NeedsVerificationCount => Versions.Count(v => v.Status == VersionSpectrumStatus.NeedsVerification);
    public int OutsideRuleCount => Versions.Count(v => v.Status == VersionSpectrumStatus.OutsideRule);
    public bool HasAnyUnparsedAdvisory => Advisories.Any(a => a.HasUnparsedRange || a.Intersection == RangeRisk.Unknown);
}

public record SpectrumApprovalBand(
    int RuleId,
    string VersionPattern,
    bool IsWildcard,
    bool IncludePrerelease,
    RuleStatus Status,
    bool IsExpired,
    DateTime? ExpiresAtUtc,
    bool IsFocused);

public record SpectrumBlockBand(
    int RuleId,
    string PackagePattern,
    string VersionPattern,
    string Justification);

public record SpectrumExclusionBand(
    int RuleId,
    int? ParentRuleId,
    string SourceId,
    string? Url,
    bool Withdrawn,
    string Justification,
    IReadOnlyList<SpectrumIntervalLabel> Intervals,
    IReadOnlyList<string> ListedVersions,
    bool HasUnparsedData);

public record SpectrumAdvisoryBand(
    string SourceId,
    string? Url,
    string Summary,
    RangeRisk Intersection,
    IReadOnlyList<SpectrumIntervalLabel> Intervals,
    IReadOnlyList<string> ListedVersions,
    bool HasUnparsedRange,
    bool HasExclusion,
    bool HasRiskAcceptance);

public record SpectrumRiskAcceptanceBand(
    int RuleId,
    string VersionPattern,
    string? AdvisorySourceId,
    string? AdvisoryUrl,
    string Justification,
    DateTime? ExpiresAtUtc);

public record SpectrumIntervalLabel(
    string DisplayRange,
    string? FixedVersion);

public record SpectrumVersionPoint(
    string Version,
    VersionSpectrumStatus Status,
    bool WithinFocusedRule,
    bool WithinAnyApproval,
    int? AuthorizingRuleId,
    int? BlockRuleId,
    int? ExclusionRuleId,
    string? ExclusionAdvisoryId,
    IReadOnlyList<Vulnerability> BlockingAdvisories,
    IReadOnlyList<AcceptedVulnerability> AcceptedVulnerabilities,
    IReadOnlyList<string> FixVersions,
    bool NeedsVerification,
    bool AuditWarning,
    bool SourcePermitted,
    string AuthorizationReason,
    string AdmissionReason,
    IReadOnlyList<InventoryUse> Uses);

public record RuleListSpectrumSignal(
    bool HasBlockOverlap,
    string? BlockReason,
    int OverlappingAdvisoryCount,
    int UnparsedAdvisoryCount,
    int ExclusionCount,
    bool ExpiringSoon);
