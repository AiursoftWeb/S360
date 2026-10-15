using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

public enum TrustRuleStatus { Pending, Approved, Rejected, Revoked }

public class TrustRule
{
    [Key]
    public int Id { get; init; }
    public required int SupplierId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(SupplierId))]
    [NotNull]
    public Supplier? Supplier { get; set; }
    /// <summary>Null for a manually created rule without a dependency application.</summary>
    public required int? ApplicationId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(ApplicationId))]
    public DependencyApplication? Application { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string PackagePattern { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = "*";
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string? Sha256 { get; set; }
    public bool IncludePrerelease { get; set; }
    [MaxLength(2000)] public string Justification { get; set; } = string.Empty;
    [MaxLength(450)] public string RequestedByUserId { get; set; } = string.Empty;
    public DateTime RequestedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
    public TrustRuleStatus Status { get; set; }
    [InverseProperty(nameof(TrustRuleReview.TrustRule))]
    public IEnumerable<TrustRuleReview> Reviews { get; init; } = new List<TrustRuleReview>();
}

public class TrustRuleReview
{
    [Key]
    public int Id { get; init; }
    public required int TrustRuleId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(TrustRuleId))]
    [NotNull]
    public TrustRule? TrustRule { get; set; }
    public TrustRuleStatus Decision { get; set; }
    [MaxLength(450)] public string ReviewerId { get; set; } = string.Empty;
    [MaxLength(2000)] public string Reason { get; set; } = string.Empty;
    [MaxLength(64)] public string? ReportHash { get; set; }
    [MaxLength(32)] public string? DecisionBatchId { get; set; }
    public DateTime ReviewedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
}
