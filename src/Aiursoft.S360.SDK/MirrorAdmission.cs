using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.SDK;

public record MirrorCandidate(
    [Required] string Ecosystem,
    [Required, StringLength(214)] string Name,
    [Required, StringLength(128)] string Version,
    [Required, StringLength(500)] string Source);
public record MirrorCandidateDecision(MirrorCandidate Candidate, bool CanFetch);
public record MirrorCandidateRequest([Required, MinLength(1), MaxLength(500)] List<MirrorCandidate> Candidates);
public record MirrorCandidateResponse(List<MirrorCandidateDecision> Decisions);
