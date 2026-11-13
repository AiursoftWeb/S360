using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Authentication;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Services.Resolution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Controllers;

[Authorize(AuthenticationSchemes = S360CheckKeyHandler.SchemeName, Policy = AppPermissionNames.CanCheckDependencies)]
[Route("api/artifacts/mirror")]
public class MirrorAdmissionController(TemplateDbContext db, TrustService trust, IConfiguration configuration,
    VulnerabilityAuditJob audit, ArtifactVerificationAdmission admission) : ControllerBase
{
    [HttpPost("candidates"), RequestSizeLimit(1024 * 1024)]
    public async Task<IActionResult> Candidates([FromBody] MirrorCandidateRequest? request)
    {
        if (request?.Candidates is not { Count: > 0 and <= 500 } || !ModelState.IsValid ||
            request.Candidates.Any(c => c == null || !TrustPattern.IsValidConcretePackage(c.Ecosystem, c.Name, c.Version)))
            return BadRequest();
        try
        {
            var decisions = await trust.EvaluateCandidatesAsync(request.Candidates);
            var result = decisions.Select(d => d with
            {
                CanFetch = d.CanFetch && MirrorPackageSources.Upstream(configuration, d.Candidate.Ecosystem, d.Candidate.Source) != null
            }).ToList();
            return Ok(new MirrorCandidateResponse(result));
        }
        catch (ArgumentException) { return BadRequest("Invalid mirror source."); }
    }

    [HttpPost("verify"), RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> Verify([FromBody] Dependency? dependency, CancellationToken token)
    {
        if (dependency == null || !ModelState.IsValid ||
            !TrustPattern.IsValidConcretePackage(dependency.Ecosystem, dependency.Name, dependency.Version)) return BadRequest();
        try
        {
            var upstream = MirrorPackageSources.Upstream(configuration, dependency.Ecosystem, dependency.Source);
            if (upstream == null) return BadRequest("No configured mirror mapping.");
            var decision = (await trust.AssessAsync([dependency])).Single();
            if (decision.Trusted || !decision.PendingVerification) return Ok(decision);
            if (!admission.TryAdmit(anonymous: false)) return StatusCode(StatusCodes.Status429TooManyRequests);
            await admission.MirrorVerifications.WaitAsync(token);
            try
            {
                await trust.ReviewAsync([dependency]);
                var source = TrustPattern.NormalizeSource(dependency.Source);
                var key = PackageArtifact.CalculateIdentityKey(dependency.Ecosystem, dependency.Name, dependency.Version, source, dependency.Sha256);
                var artifact = await db.PackageArtifacts.AsNoTracking().SingleOrDefaultAsync(a => a.IdentityKey == key, token);
                if (artifact == null) return Ok((await trust.AssessAsync([dependency])).Single());
                artifact.VerificationSource = upstream;
                await audit.CheckArtifactAsync(artifact, token);
                return Ok((await trust.AssessAsync([dependency])).Single());
            }
            finally { admission.MirrorVerifications.Release(); }
        }
        catch (ArgumentException) { return BadRequest("Invalid mirror source."); }
        catch (InvalidDataException)
        {
            return Ok(new DependencyDecision { Dependency = dependency, Reason = "Archive differs from the configured upstream." });
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidOperationException or System.Text.Json.JsonException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Independent mirror verification is unavailable." });
        }
    }
}
