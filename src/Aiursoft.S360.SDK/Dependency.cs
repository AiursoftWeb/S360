using System.ComponentModel.DataAnnotations;
using Aiursoft.AiurProtocol.Models;

namespace Aiursoft.S360.SDK;

public class Dependency
{
    [Required, RegularExpression("^(nuget|npm)$")]
    public string Ecosystem { get; set; } = string.Empty;

    [Required, StringLength(214)]
    public string Name { get; set; } = string.Empty;

    [Required, StringLength(128)]
    public string Version { get; set; } = string.Empty;

    [Required, StringLength(500)]
    public string Source { get; set; } = string.Empty;

    [Required, RegularExpression("^[a-fA-F0-9]{64}$")]
    public string Sha256 { get; set; } = string.Empty;
}

public class CheckRequest
{
    public SolutionDependencyGraph? SolutionGraph { get; set; }
    /// <summary>Null for older clients. Non-null batches together contain the complete observed graph.</summary>
    [MaxLength(5000)] public List<DependencyGraphNode>? GraphNodes { get; set; }

    [Required, MaxLength(5000)]
    public List<Dependency> Dependencies { get; set; } = [];

    [Range(1, 10000)] public int ScannedProjectCount { get; set; }

    [StringLength(750)] public string? Project { get; set; }
    [StringLength(80)] public string? Commit { get; set; }
    [StringLength(200)] public string? Pipeline { get; set; }
    public CheckContext? Context { get; set; }
    [Required, RegularExpression("^[a-fA-F0-9]{32}$")]
    public string RunId { get; set; } = Guid.NewGuid().ToString("N");
    [Range(0, 10000)] public int BatchIndex { get; set; }
    [Range(1, 10000)] public int BatchCount { get; set; } = 1;
}

public class DependencyDecision
{
    public Dependency Dependency { get; set; } = new();
    public bool Trusted { get; set; }
    /// <summary>Policy permits this package, but independent verification or audit is still pending.</summary>
    public bool PendingVerification { get; set; }
    public string Reason { get; set; } = string.Empty;
    public int? RuleId { get; set; }
}

public class CheckResponse : AiurResponse
{
    public int SolutionGraphVersion { get; set; }
    public bool Trusted { get; set; }
    public List<DependencyDecision> Decisions { get; set; } = [];
}

/// <summary>Client-reported check provenance; this is not deployment attestation.</summary>
public class CheckContext
{
    /// <summary>Repository is provenance; the repository-relative solution path identifies the audited project.</summary>
    [StringLength(200)] public string? Repository { get; set; }
    [StringLength(512)] public string? SolutionPath { get; set; }
    /// <summary>Baseline declares production use; review never changes production inventory.</summary>
    [RegularExpression("^(review|baseline)$")] public string? Purpose { get; set; }
    /// <summary>Set by the server from authentication, never trusted from the caller.</summary>
    public bool IsAnonymous { get; set; }

    /// <summary>Authenticated account and key identifiers, set by the server.</summary>
    public string? UserId { get; set; }
    public string? ApiKeyId { get; set; }
    /// <summary>Null covers both supported ecosystems; a scoped baseline replaces only that ecosystem.</summary>
    [RegularExpression("^(nuget|npm)$")] public string? Ecosystem { get; set; }
    [Required, RegularExpression("^(local|gitlab)$")]
    public string Provider { get; set; } = "local";
    [StringLength(80)] public string? PipelineSource { get; set; }
    [StringLength(255)] public string? Ref { get; set; }
    [StringLength(255)] public string? DefaultBranch { get; set; }
    [StringLength(40)] public string? MergeRequest { get; set; }
    [StringLength(255)] public string? Tag { get; set; }
}
