using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.SDK;

public class ArtifactAssessmentRequest
{
    [Required, MinLength(1), MaxLength(500)]
    public List<Dependency> Dependencies { get; set; } = [];
}

public class ArtifactAssessmentResponse
{
    public List<DependencyDecision> Decisions { get; set; } = [];
}

public class ApprovedArtifactPage
{
    public List<Dependency> Artifacts { get; set; } = [];
    public int? NextAfterId { get; set; }
    public int UpperId { get; set; }
}
