using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public enum ApplicationStatus { Resolving, ReadyForReview, Failed, Approved, Rejected, Withdrawn, Revoked }

public class DependencyApplication
{
    public int Id { get; set; }
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
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ResolvedAtUtc { get; set; }
    public DateTime? DecidedAtUtc { get; set; }
    [MaxLength(450)] public string? DecidedByUserId { get; set; }
    [MaxLength(2000)] public string? DecisionReason { get; set; }
    public List<ApplicationPackage> Packages { get; set; } = [];
    public List<ApplicationEdge> Edges { get; set; } = [];
}

public class ApplicationPackage
{
    public int Id { get; set; }
    public int ApplicationId { get; set; }
    public DependencyApplication? Application { get; set; }
    public int PackageArtifactId { get; set; }
    public PackageArtifact? PackageArtifact { get; set; }
    public bool IsDirect { get; set; }
}

public class ApplicationEdge
{
    public int Id { get; set; }
    public int ApplicationId { get; set; }
    public DependencyApplication? Application { get; set; }
    public int? ParentPackageId { get; set; }
    public PackageArtifact? ParentPackage { get; set; }
    public int ChildPackageId { get; set; }
    public PackageArtifact? ChildPackage { get; set; }
}
