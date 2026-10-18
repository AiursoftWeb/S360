using System.Text.Json;
using Aiursoft.AiurProtocol.Models;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.Canon.BackgroundJobs;
using Microsoft.Extensions.Caching.Memory;
using Aiursoft.S360.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Services.Authentication;

namespace Aiursoft.S360.Controllers;

[Authorize(AuthenticationSchemes = S360CheckKeyHandler.SchemeName,
    Policy = AppPermissionNames.CanCheckDependencies)]
[Route("api/check")]
public class CheckController(TrustService trust, TemplateDbContext db,
    BackgroundJobRegistry jobs, IMemoryCache cache, IConfiguration configuration) : ControllerBase
{
    [HttpPost]
    [RequestSizeLimit(4 * 1024 * 1024)]
    public async Task<IActionResult> Check([FromBody] CheckRequest request)
    {
        if (!ModelState.IsValid || request.ScannedProjectCount < 1 ||
            request.BatchIndex >= request.BatchCount ||
            (request.Dependencies.Count == 0 && (request.BatchIndex != 0 || request.BatchCount != 1)) ||
            request.Dependencies.Cast<Dependency?>().Any(d => d is null ||
                !TrustPattern.IsValidConcretePackage(d.Ecosystem, d.Name, d.Version)))
            return BadRequest();
        if (request.Context?.Purpose == "baseline")
        {
            if (!User.HasClaim(S360CheckKeyHandler.BaselineClaim, "true"))
                return Forbid(S360CheckKeyHandler.SchemeName);
            if (string.IsNullOrWhiteSpace(request.Project))
                return BadRequest("A production baseline must identify its project.");
        }
        if (request.Context?.Ecosystem is { Length: > 0 } ecosystem &&
            request.Dependencies.Any(dependency => dependency.Ecosystem != ecosystem))
            return BadRequest("Dependencies must belong to the declared ecosystem.");
        var contextJson = request.Context == null ? null : JsonSerializer.Serialize(request.Context);
        var priorBatches = await db.BuildChecks.AsNoTracking().Where(c => c.RunId == request.RunId)
            .Select(c => new { c.Project, c.Commit, c.Pipeline, c.BatchCount, c.BatchIndex, c.ScannedProjectCount, c.ContextJson }).ToListAsync();
        if (priorBatches.Any(prior => prior.BatchCount != request.BatchCount || prior.Project != request.Project ||
            prior.Commit != request.Commit || prior.Pipeline != request.Pipeline ||
            prior.ScannedProjectCount != request.ScannedProjectCount || prior.ContextJson != contextJson))
            return BadRequest("Batches in one run must have identical project, commit, pipeline, check context, scanned project count and batch count.");
        if (priorBatches.Any(prior => prior.BatchIndex == request.BatchIndex))
            return Conflict("This batch index has already been reported for the run. Start a new run to recheck current policy.");
        if (priorBatches.Count != request.BatchIndex ||
            !priorBatches.Select(prior => prior.BatchIndex).OrderBy(index => index)
                .SequenceEqual(Enumerable.Range(0, request.BatchIndex)))
            return BadRequest("Batches must be reported in order, starting at index zero.");
        try
        {
            var sourceAllowed = request.Dependencies.Select(dependency =>
                AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source)).ToArray();
            var permittedDependencies = request.Dependencies.Where((_, index) => sourceAllowed[index]).ToList();
            var permittedDecisions = permittedDependencies.Count == 0
                ? [] : await trust.CheckAsync(permittedDependencies);
            var permittedIndex = 0;
            var decisions = request.Dependencies.Select((dependency, index) => sourceAllowed[index]
                ? permittedDecisions[permittedIndex++]
                : new DependencyDecision
                {
                    Dependency = dependency, Trusted = false,
                    Reason = "Package source is not permitted for CI verification."
                }).ToList();
            var runTrusted = decisions.All(d => d.Trusted);
            string? runDenialReason = null;
            var requestedKeys = permittedDependencies.Select(dependency => ArtifactKey(
                dependency.Ecosystem, dependency.Name, dependency.Version,
                TrustPattern.NormalizeSource(dependency.Source), dependency.Sha256)).Distinct().ToList();
            var artifactLookup = new Dictionary<string, PackageArtifact>(StringComparer.Ordinal);
            // Keep the query bounded to this batch, even when the catalog has grown large.
            foreach (var keys in requestedKeys.Chunk(500))
            {
                var existing = await db.PackageArtifacts.Where(a => keys.Contains(a.IdentityKey)).ToListAsync();
                foreach (var artifact in existing) artifactLookup.Add(artifact.IdentityKey, artifact);
            }
            var check = new BuildCheck
            {
                Project = request.Project, Commit = request.Commit, Pipeline = request.Pipeline, ContextJson = contextJson,
                RunId = request.RunId, BatchIndex = request.BatchIndex, BatchCount = request.BatchCount,
                ScannedProjectCount = request.ScannedProjectCount,
                Trusted = runTrusted,
                VulnerabilityDataCheckedAtUtc = await db.VulnerabilitySyncStates.AsNoTracking()
                    .Select(s => s.LastSuccessAtUtc).FirstOrDefaultAsync()
            };
            for (var decisionIndex = 0; decisionIndex < decisions.Count; decisionIndex++)
            {
                var decision = decisions[decisionIndex];
                var dependency = decision.Dependency;
                var source = TrustPattern.NormalizeSource(dependency.Source);
                PackageArtifact? artifact = null;
                if (sourceAllowed[decisionIndex])
                {
                    var key = ArtifactKey(dependency.Ecosystem, dependency.Name, dependency.Version,
                        source, dependency.Sha256);
                    if (!artifactLookup.TryGetValue(key, out artifact))
                    {
                        // Observation is not authorization. An unapproved or blocked package
                        // still needs a durable artifact so scheduled vulnerability audit sees it.
                        // A source outside policy is recorded in the check only: never fetch it.
                        artifact = new PackageArtifact
                        {
                            Ecosystem = dependency.Ecosystem, Name = dependency.Name,
                            Version = dependency.Version, Source = source,
                            Sha256 = dependency.Sha256.ToLowerInvariant()
                        };
                        db.PackageArtifacts.Add(artifact);
                        artifactLookup.Add(key, artifact);
                    }
                }
                db.BuildCheckDependencies.Add(new BuildCheckDependency
                {
                    BuildCheckId = check.Id, BuildCheck = check, PackageArtifactId = artifact?.Id,
                    PackageArtifact = artifact, Ecosystem = dependency.Ecosystem,
                    Name = dependency.Name, Version = dependency.Version, Source = source,
                    Sha256 = dependency.Sha256.ToLowerInvariant(), Trusted = decision.Trusted,
                    Reason = decision.Reason[..Math.Min(decision.Reason.Length, 1000)]
                });
            }
            if (request.BatchIndex == request.BatchCount - 1)
            {
                // A policy change between batches must not let an earlier approval
                // remain valid just because the last batch passed on its own.
                var previous = await db.BuildChecks.AsNoTracking().Include(c => c.Dependencies)
                    .Where(c => c.RunId == request.RunId).ToListAsync();
                var complete = BuildCheckRun.IsComplete(previous.Append(check).ToList());
                if (!complete)
                {
                    runTrusted = false;
                    runDenialReason = "The dependency-check run is incomplete; rerun the full check.";
                }
                else
                {
                    var entireRun = previous.SelectMany(c => c.Dependencies).Select(d => new Dependency
                    {
                        Ecosystem = d.Ecosystem, Name = d.Name, Version = d.Version,
                        Source = d.Source, Sha256 = d.Sha256
                    }).Concat(request.Dependencies).ToList();
                    // A source can be removed after an earlier batch was accepted.
                    // Recheck the complete run against the current source policy,
                    // not only the current batch's sources.
                    var disallowedSource = entireRun.FirstOrDefault(dependency =>
                        !AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source));
                    if (disallowedSource != null)
                    {
                        runTrusted = false;
                        runDenialReason = $"Package {disallowedSource.Ecosystem} {disallowedSource.Name}@{disallowedSource.Version} " +
                            $"from {disallowedSource.Source}: package source is no longer permitted.";
                    }
                    else
                    {
                        var denied = (await trust.AssessAsync(entireRun)).FirstOrDefault(d => !d.Trusted);
                        runTrusted = denied == null;
                        if (denied != null)
                            runDenialReason = $"Package {denied.Dependency.Ecosystem} " +
                                $"{denied.Dependency.Name}@{denied.Dependency.Version} " +
                                $"from {denied.Dependency.Source}: {denied.Reason}";
                    }
                }
                check.Trusted = runTrusted;
            }
            db.BuildChecks.Add(check);
            await db.SaveChangesAsync();
            if ((check.Dependencies.Any(d => d.PackageArtifact is { SourceVerifiedAtUtc: null } ||
                    d.PackageArtifact is { LastCheckedAtUtc: null }) ||
                 decisions.Any(d => d.Reason.Contains("Vulnerability audit", StringComparison.Ordinal))) &&
                !cache.TryGetValue("s360-osv-audit-queued", out _))
            {
                cache.Set("s360-osv-audit-queued", true, TimeSpan.FromMinutes(5));
                jobs.TriggerNow<VulnerabilityAuditJob>();
            }
            return Ok(new CheckResponse
            {
                Code = Code.ResultShown,
                Message = runTrusted ? "Dependency trust checked." :
                    runDenialReason ?? "This batch does not pass current policy; rerun the complete check.",
                Trusted = runTrusted,
                Decisions = decisions
            });
        }
        catch (ArgumentException)
        {
            return BadRequest("Invalid package source.");
        }
    }

    private static string ArtifactKey(string ecosystem, string name, string version,
        string source, string sha256) =>
        PackageArtifact.CalculateIdentityKey(ecosystem, name, version, source, sha256);
}
