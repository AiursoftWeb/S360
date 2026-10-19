using System.Text.Json;
using System.Security.Claims;
using Aiursoft.S360.Configuration;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authentication;
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
    BackgroundJobRegistry jobs, IMemoryCache cache, IConfiguration configuration,
    GlobalSettingsService settings, IAuthorizationService authorization) : ControllerBase
{
    [HttpPost, AllowAnonymous, LimitPerMin(120)]
    [RequestSizeLimit(4 * 1024 * 1024)]
    public async Task<IActionResult> Check([FromBody] CheckRequest? request)
    {
        // Only review checks may bypass machine authentication.
        var purpose = request?.Context?.Purpose;
        if (string.IsNullOrEmpty(purpose)) purpose = "review";
        var authentication = await HttpContext.AuthenticateAsync(S360CheckKeyHandler.SchemeName);
        var anonymous = !authentication.Succeeded;
        if (anonymous)
        {
            if (Request.Headers.ContainsKey("X-S360-Key") || purpose != "review" ||
                !await settings.GetBoolSettingAsync(SettingsMap.AllowAnonymousReview))
                return Challenge(S360CheckKeyHandler.SchemeName);
        }
        else
        {
            HttpContext.User = authentication.Principal!;
            if (!(await authorization.AuthorizeAsync(User, AppPermissionNames.CanCheckDependencies)).Succeeded)
                return Forbid(S360CheckKeyHandler.SchemeName);
        }
        if (request == null || !ModelState.IsValid || request.ScannedProjectCount < 1 ||
            request.BatchIndex >= request.BatchCount ||
            (request.Dependencies.Count == 0 && request.GraphNodes is not { Count: > 0 } &&
                (request.BatchIndex != 0 || request.BatchCount != 1)) ||
            request.Dependencies.Cast<Dependency?>().Any(d => d is null ||
                !TrustPattern.IsValidConcretePackage(d.Ecosystem, d.Name, d.Version)))
            return BadRequest();
        request.Context ??= new CheckContext();
        request.Context.Purpose = purpose;
        request.Context.IsAnonymous = anonymous;
        request.Context.UserId = anonymous ? null : User.FindFirstValue(ClaimTypes.NameIdentifier);
        request.Context.ApiKeyId = anonymous ? null : User.FindFirstValue(S360CheckKeyHandler.KeyIdClaim);
        if (purpose == "baseline")
        {
            if (!User.HasClaim(S360CheckKeyHandler.BaselineClaim, "true"))
                return Forbid(S360CheckKeyHandler.SchemeName);
            if (string.IsNullOrWhiteSpace(request.Project))
                return BadRequest("A production baseline must identify its project.");
        }
        if (request.Context.Ecosystem is { Length: > 0 } ecosystem &&
            request.Dependencies.Any(dependency => dependency.Ecosystem != ecosystem))
            return BadRequest("Dependencies must belong to the declared ecosystem.");
        if (purpose == "review")
        {
            // Review is a read-only, per-batch policy query. The CLI validates the
            // complete graph and aggregates all decisions; no run is stored here.
            if (request.GraphNodes != null)
            {
                var completeGraph = request.BatchCount == 1;
                var graphError = DependencyGraphNode.Validate(request.GraphNodes, request.Dependencies,
                    request.Context.Ecosystem, completeGraph);
                if (graphError != null) return BadRequest(graphError);
                if (completeGraph && request.GraphNodes.Select(n => (n.Project, n.Ecosystem)).Distinct().Count() != request.ScannedProjectCount)
                    return BadRequest("Graph manifests must match the scanned project count.");
            }
            try
            {
                var decisions = await CheckDependenciesAsync(request.Dependencies, persist: false);
                return Ok(new CheckResponse
                {
                    Code = Code.ResultShown, Trusted = decisions.All(d => d.Trusted), Decisions = decisions,
                    Message = "Dependency review completed. No project report was saved."
                });
            }
            catch (ArgumentException)
            {
                return BadRequest("Invalid package source.");
            }
        }
        var contextJson = JsonSerializer.Serialize(request.Context);
        var priorBatches = await db.BuildChecks.AsNoTracking().Where(c => c.RunId == request.RunId)
            .Select(c => new { c.Project, c.Commit, c.Pipeline, c.BatchCount, c.BatchIndex, c.ScannedProjectCount, c.ContextJson, HasGraph = c.GraphJson != null }).ToListAsync();
        if (priorBatches.Any(prior => prior.BatchCount != request.BatchCount || prior.Project != request.Project ||
            prior.Commit != request.Commit || prior.Pipeline != request.Pipeline ||
            prior.ScannedProjectCount != request.ScannedProjectCount || prior.ContextJson != contextJson ||
            prior.HasGraph != (request.GraphNodes != null)))
            return BadRequest("Batches in one run must have identical project, commit, pipeline, check context, scanned project count and batch count.");
        if (priorBatches.Any(prior => prior.BatchIndex == request.BatchIndex))
            return Conflict("This batch index has already been reported for the run. Start a new run to recheck current policy.");
        if (priorBatches.Count != request.BatchIndex ||
            !priorBatches.Select(prior => prior.BatchIndex).OrderBy(index => index)
                .SequenceEqual(Enumerable.Range(0, request.BatchIndex)))
            return BadRequest("Batches must be reported in order, starting at index zero.");
        if (request.GraphNodes != null)
        {
            var nodes = request.GraphNodes.ToList();
            var graphDependencies = request.Dependencies.ToList();
            var completeGraph = request.BatchIndex == request.BatchCount - 1;
            if (completeGraph && priorBatches.Count > 0)
            {
                var prior = await db.BuildChecks.AsNoTracking().Include(c => c.Dependencies)
                    .Where(c => c.RunId == request.RunId).ToListAsync();
                nodes.AddRange(prior.SelectMany(c => JsonSerializer.Deserialize<List<DependencyGraphNode>>(c.GraphJson!)!));
                graphDependencies.AddRange(prior.SelectMany(c => c.Dependencies).Select(d => new Dependency
                {
                    Ecosystem = d.Ecosystem, Name = d.Name, Version = d.Version, Source = d.Source, Sha256 = d.Sha256
                }));
            }
            // Validate before policy evaluation or artifact writes. Relationships never grant trust.
            var graphError = DependencyGraphNode.Validate(nodes, graphDependencies, request.Context.Ecosystem, completeGraph);
            if (graphError != null) return BadRequest(graphError);
            if (completeGraph && nodes.Select(n => (n.Project, n.Ecosystem)).Distinct().Count() != request.ScannedProjectCount)
                return BadRequest("Graph manifests must match the scanned project count.");
        }
        try
        {
            var sourceAllowed = request.Dependencies.Select(dependency =>
                AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source)).ToArray();
            var decisions = await CheckDependenciesAsync(request.Dependencies, persist: true);
            var runTrusted = decisions.All(d => d.Trusted);
            string? runDenialReason = null;
            var requestedKeys = request.Dependencies.Where((_, index) => sourceAllowed[index]).Select(dependency => ArtifactKey(
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
                GraphJson = request.GraphNodes == null ? null : JsonSerializer.Serialize(request.GraphNodes),
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

    private async Task<List<DependencyDecision>> CheckDependenciesAsync(List<Dependency> dependencies, bool persist)
    {
        var sourceAllowed = dependencies.Select(dependency =>
            AllowedPackageSources.Contains(configuration, dependency.Ecosystem, dependency.Source)).ToArray();
        var permitted = dependencies.Where((_, index) => sourceAllowed[index]).ToList();
        var assessed = permitted.Count == 0 ? [] : persist
            ? await trust.CheckAsync(permitted) : await trust.AssessAsync(permitted);
        var index = 0;
        return dependencies.Select((dependency, position) => sourceAllowed[position]
            ? assessed[index++]
            : new DependencyDecision
            {
                Dependency = dependency, Trusted = false,
                Reason = "Package source is not permitted for CI verification."
            }).ToList();
    }

    private static string ArtifactKey(string ecosystem, string name, string version,
        string source, string sha256) =>
        PackageArtifact.CalculateIdentityKey(ecosystem, name, version, source, sha256);
}
