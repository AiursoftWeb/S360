using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

public enum RuleStatus { Pending, Approved, Rejected, Revoked }
public enum RuleKind { Approval, Block, VulnerabilityExclusion, RiskAcceptance }

public class PackageRule
{
    [Key] public int Id { get; init; }
    public RuleKind Kind { get; set; }
    public RuleStatus Status { get; set; }
    public int? ApplicationId { get; set; }
    [JsonIgnore, ForeignKey(nameof(ApplicationId))]
    public DependencyApplication? Application { get; set; }
    public int? LegacySourceRuleId { get; set; }
    [JsonIgnore, ForeignKey(nameof(LegacySourceRuleId))]
    public PackageRule? LegacySourceRule { get; set; }
    /// <summary>A vulnerability exclusion follows this approval's scope and lifetime.</summary>
    public int? ParentRuleId { get; set; }
    [JsonIgnore, ForeignKey(nameof(ParentRuleId))]
    public PackageRule? ParentRule { get; set; }
    public int? VulnerabilityId { get; set; }
    [JsonIgnore, ForeignKey(nameof(VulnerabilityId))]
    public Vulnerability? Vulnerability { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string PackagePattern { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = "*";
    /// <summary>Approval source. Global blocks apply to every source.</summary>
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    public bool IncludePrerelease { get; set; }
    [MaxLength(2000)] public string Justification { get; set; } = string.Empty;
    [MaxLength(450)] public string RequestedByUserId { get; set; } = string.Empty;
    public DateTime RequestedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
    [InverseProperty(nameof(RuleChange.Rule))]
    public IEnumerable<RuleChange> Reviews { get; init; } = new List<RuleChange>();
    [NotMapped] public bool IsLegacyTemplate => PackagePattern.Contains('*');

    public bool MatchesPackage(string name)
    {
        var comparison = Ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        // Historical wildcard approvals grant nothing; their denials still apply.
        if (IsLegacyTemplate)
            return Status is RuleStatus.Rejected or RuleStatus.Revoked &&
                PackagePattern.EndsWith('*') && name.StartsWith(PackagePattern[..^1], comparison);
        return PackagePattern.Equals(name, comparison);
    }
}

public class RuleChange
{
    [Key] public int Id { get; init; }
    public int RuleId { get; set; }
    [JsonIgnore, ForeignKey(nameof(RuleId))]
    public PackageRule Rule { get; set; } = null!;
    // Historical block edits recorded prose, not a structured decision.
    public RuleStatus? Decision { get; set; }
    [MaxLength(450)] public string ReviewerId { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    [MaxLength(64)] public string? ReportHash { get; set; }
    [MaxLength(32)] public string? DecisionBatchId { get; set; }
    public DateTime ReviewedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
}
