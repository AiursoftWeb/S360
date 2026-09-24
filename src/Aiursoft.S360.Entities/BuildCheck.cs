using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public class BuildCheck
{
    public int Id { get; set; }
    [MaxLength(200)] public string? Project { get; set; }
    [MaxLength(80)] public string? Commit { get; set; }
    [MaxLength(200)] public string? Pipeline { get; set; }
    [MaxLength(32)] public string RunId { get; set; } = string.Empty;
    public int BatchIndex { get; set; }
    public int BatchCount { get; set; } = 1;
    public int ScannedProjectCount { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public bool Trusted { get; set; }
    public DateTime? VulnerabilityDataCheckedAtUtc { get; set; }
    public List<BuildCheckDependency> Dependencies { get; set; } = [];
}

public class BuildCheckDependency
{
    public int Id { get; set; }
    public int BuildCheckId { get; set; }
    public BuildCheck? BuildCheck { get; set; }
    public int? PackageArtifactId { get; set; }
    public PackageArtifact? PackageArtifact { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string Name { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string Sha256 { get; set; } = string.Empty;
    public bool Trusted { get; set; }
    [MaxLength(1000)] public string Reason { get; set; } = string.Empty;
}
