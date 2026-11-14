using Aiursoft.S360.Authorization;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Authentication;
using Aiursoft.S360.Services.Resolution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Aiursoft.S360.Controllers;

// Compatibility routes for deployed registries. Both only query compliance; neither downloads packages.
[Authorize(AuthenticationSchemes = S360CheckKeyHandler.SchemeName, Policy = AppPermissionNames.CanCheckDependencies)]
[Route("api/artifacts/mirror")]
public class MirrorAdmissionController(TrustService trust, IConfiguration configuration) : ControllerBase
{
    [HttpPost("candidates"), RequestSizeLimit(1024 * 1024)]
    public async Task<IActionResult> Candidates([FromBody] MirrorCandidateRequest? request)
    {
        if (request?.Candidates is not { Count: > 0 and <= 500 } || !ModelState.IsValid ||
            request.Candidates.Cast<MirrorCandidate?>().Any(c => c == null ||
                !TrustPattern.IsValidConcretePackage(c.Ecosystem, c.Name, c.Version))) return BadRequest();
        try
        {
            var dependencies = request.Candidates.Select(c => new Dependency
                { Ecosystem = c.Ecosystem, Name = c.Name, Version = c.Version, Source = c.Source }).ToList();
            var decisions = await trust.AssessAsync(dependencies);
            if (decisions.Any(d => d.PendingVerification))
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Current vulnerability data is unavailable." });
            return Ok(new MirrorCandidateResponse(decisions.Select((d, i) =>
                new MirrorCandidateDecision(request.Candidates[i], d.Trusted &&
                    AllowedPackageSources.Contains(configuration, d.Dependency.Ecosystem, d.Dependency.Source))).ToList()));
        }
        catch (ArgumentException) { return BadRequest("Invalid package source."); }
    }

    [HttpPost("verify"), RequestSizeLimit(16 * 1024)]
    public async Task<IActionResult> Verify([FromBody] Dependency? dependency)
    {
        if (dependency == null || !ModelState.IsValid ||
            !TrustPattern.IsValidConcretePackage(dependency.Ecosystem, dependency.Name, dependency.Version)) return BadRequest();
        try
        {
            if (!AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source))
                return Ok(new DependencyDecision { Dependency = dependency, Reason = "Package source is not permitted." });
            var decision = (await trust.AssessAsync([dependency])).Single();
            return decision.PendingVerification
                ? StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "Current vulnerability data is unavailable." })
                : Ok(decision);
        }
        catch (ArgumentException) { return BadRequest("Invalid package source."); }
    }
}
