using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

public enum ApplicationStatus { Resolving, ReadyForReview, Failed, Approved, Rejected, Withdrawn, Revoked }

public class DependencyApplication
{
    [Key]
    public int Id { get; init; }
    [MaxLength(450)] public string RequestedByUserId { get; set; } = string.Empty;
    [MaxLength(2000)] public string Justification { get; set; } = string.Empty;
    [MaxLength(200)] public string? Project { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(2000)] public string DirectPackages { get; set; } = string.Empty;
    [MaxLength(200)] public string ResolutionContext { get; set; } = string.Empty;
    [MaxLength(64)] public string? ReportHash { get; set; }
    [MaxLength(2000)] public string? Failure { get; set; }
    public ApplicationStatus Status { get; set; } = ApplicationStatus.Resolving;
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? ResolvedAtUtc { get; set; }
    public DateTime? DecidedAtUtc { get; set; }
    [MaxLength(450)] public string? DecidedByUserId { get; set; }
    [MaxLength(2000)] public string? DecisionReason { get; set; }
    [InverseProperty(nameof(ApplicationPackage.Application))]
    public IEnumerable<ApplicationPackage> Packages { get; init; } = new List<ApplicationPackage>();
    [InverseProperty(nameof(ApplicationEdge.Application))]
    public IEnumerable<ApplicationEdge> Edges { get; init; } = new List<ApplicationEdge>();
}

public class ApplicationPackage
{
    [Key]
    public int Id { get; init; }
    public required int ApplicationId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(ApplicationId))]
    [NotNull]
    public DependencyApplication? Application { get; set; }
    public required int PackageArtifactId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(PackageArtifactId))]
    [NotNull]
    public PackageArtifact? PackageArtifact { get; set; }
    public bool IsDirect { get; set; }
}

public class ApplicationEdge
{
    [Key]
    public int Id { get; init; }
    public required int ApplicationId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(ApplicationId))]
    [NotNull]
    public DependencyApplication? Application { get; set; }
    /// <summary>Null for a direct dependency at the root of the resolved graph.</summary>
    public required int? ParentPackageId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(ParentPackageId))]
    public PackageArtifact? ParentPackage { get; set; }
    public required int ChildPackageId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(ChildPackageId))]
    [NotNull]
    public PackageArtifact? ChildPackage { get; set; }
}
