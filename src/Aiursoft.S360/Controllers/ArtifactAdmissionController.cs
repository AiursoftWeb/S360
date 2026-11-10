using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Authentication;
using Aiursoft.S360.Services.Resolution;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Controllers;

/// <summary>Read-only global artifact admission. This never grants project build permission.</summary>
[Authorize(AuthenticationSchemes = S360CheckKeyHandler.SchemeName,
    Policy = AppPermissionNames.CanCheckDependencies)]
[Route("api/artifacts")]
public class ArtifactAdmissionController(TemplateDbContext db, TrustService trust,
    IConfiguration configuration) : ControllerBase
{
    [HttpPost("assess"), RequestSizeLimit(1024 * 1024)]
    public async Task<IActionResult> Assess([FromBody] ArtifactAssessmentRequest? request)
    {
        if (request?.Dependencies is not { Count: > 0 and <= 500 } || !ModelState.IsValid ||
            request.Dependencies.Cast<Dependency?>().Any(d => d == null ||
                !TrustPattern.IsValidConcretePackage(d.Ecosystem, d.Name, d.Version)))
            return BadRequest();
        try
        {
            var permitted = request.Dependencies.Select(d =>
                AllowedPackageSources.Contains(configuration, d.Ecosystem, d.Source)).ToArray();
            var assessed = await trust.AssessAsync(request.Dependencies.Where((_, i) => permitted[i]));
            var index = 0;
            return Ok(new ArtifactAssessmentResponse
            {
                Decisions = request.Dependencies.Select((dependency, i) => permitted[i]
                    ? assessed[index++] : new DependencyDecision
                    {
                        Dependency = dependency, Reason = "Package source is not permitted for verification."
                    }).ToList()
            });
        }
        catch (ArgumentException) { return BadRequest("Invalid package source."); }
    }

    [HttpGet("approved")]
    public async Task<IActionResult> Approved(string ecosystem, string source, int afterId = 0,
        int? upperId = null, int take = 100, string? name = null, CancellationToken cancellationToken = default)
    {
        if (ecosystem is not ("nuget" or "npm") || string.IsNullOrWhiteSpace(source) ||
            afterId < 0 || upperId < afterId || take is < 1 or > 500 ||
            (name != null && !TrustPattern.IsValidConcretePackage(ecosystem, name, "1.0.0")))
            return BadRequest();
        try
        {
            if (!AllowedPackageSources.Contains(configuration, ecosystem, source))
                return BadRequest("Package source is not permitted for verification.");
            source = TrustPattern.NormalizeSource(source);
            var query = db.PackageArtifacts.AsNoTracking().Where(a => a.Ecosystem == ecosystem &&
                a.Source == source && a.SourceVerifiedAtUtc != null && !a.SourceVerificationRejected);
            if (name != null)
            {
                var normalizedName = ecosystem == "nuget" ? name.ToLowerInvariant() : name;
                query = ecosystem == "nuget" ? query.Where(a => a.Name.ToLower() == normalizedName)
                    : query.Where(a => a.Name == normalizedName);
            }
            var ceiling = upperId ?? await query.Select(a => (int?)a.Id).MaxAsync(cancellationToken) ?? 0;
            var rows = await query.Where(a => a.Id > afterId && a.Id <= ceiling)
                .OrderBy(a => a.Id).Take(take + 1).ToListAsync(cancellationToken);
            var page = rows.Take(take).Select(a => new Dependency
            {
                Ecosystem = a.Ecosystem, Name = a.Name, Version = a.Version,
                Source = a.Source, Sha256 = a.Sha256
            }).ToList();
            var decisions = await trust.AssessAsync(page);
            return Ok(new ApprovedArtifactPage
            {
                Artifacts = decisions.Where(d => d.Trusted).Select(d => d.Dependency).ToList(),
                // A page may contain no approved artifacts but still have more candidates.
                NextAfterId = rows.Count > take ? rows[take - 1].Id : null,
                UpperId = ceiling
            });
        }
        catch (ArgumentException) { return BadRequest("Invalid package source."); }
    }
}
