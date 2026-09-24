using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public enum TrustRuleStatus { Pending, Approved, Rejected, Revoked }

public class TrustRule
{
    public int Id { get; set; }
    public int SupplierId { get; set; }
    public Supplier? Supplier { get; set; }
    public int? ApplicationId { get; set; }
    public DependencyApplication? Application { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string PackagePattern { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = "*";
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string? Sha256 { get; set; }
    public bool IncludePrerelease { get; set; }
    [MaxLength(2000)] public string Justification { get; set; } = string.Empty;
    [MaxLength(450)] public string RequestedByUserId { get; set; } = string.Empty;
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
    public TrustRuleStatus Status { get; set; }
    public List<TrustRuleReview> Reviews { get; set; } = [];
}

public class TrustRuleReview
{
    public int Id { get; set; }
    public int TrustRuleId { get; set; }
    public TrustRule? TrustRule { get; set; }
    public TrustRuleStatus Decision { get; set; }
    [MaxLength(450)] public string ReviewerId { get; set; } = string.Empty;
    [MaxLength(2000)] public string Reason { get; set; } = string.Empty;
    [MaxLength(64)] public string? ReportHash { get; set; }
    [MaxLength(32)] public string? DecisionBatchId { get; set; }
    public DateTime ReviewedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
}
