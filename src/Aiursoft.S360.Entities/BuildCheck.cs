using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

public class BuildCheck
{
    [Key]
    public int Id { get; init; }
    [MaxLength(200)] public string? Project { get; set; }
    [MaxLength(80)] public string? Commit { get; set; }
    [MaxLength(200)] public string? Pipeline { get; set; }
    [MaxLength(6000)] public string? ContextJson { get; set; }
    [MaxLength(32)] public string RunId { get; set; } = string.Empty;
    public int BatchIndex { get; set; }
    public int BatchCount { get; set; } = 1;
    public int ScannedProjectCount { get; set; }
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    public bool Trusted { get; set; }
    public DateTime? VulnerabilityDataCheckedAtUtc { get; set; }
    [InverseProperty(nameof(BuildCheckDependency.BuildCheck))]
    public IEnumerable<BuildCheckDependency> Dependencies { get; init; } = new List<BuildCheckDependency>();
}

public class BuildCheckDependency
{
    [Key]
    public int Id { get; init; }
    public required int BuildCheckId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(BuildCheckId))]
    [NotNull]
    public BuildCheck? BuildCheck { get; set; }
    /// <summary>Null when the package source was not permitted and no artifact was fetched.</summary>
    public required int? PackageArtifactId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(PackageArtifactId))]
    public PackageArtifact? PackageArtifact { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string Name { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string Sha256 { get; set; } = string.Empty;
    public bool Trusted { get; set; }
    [MaxLength(1000)] public string Reason { get; set; } = string.Empty;
}
