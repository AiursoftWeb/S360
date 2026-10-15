using System.Text.Json;
using Aiursoft.Canon.BackgroundJobs;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services.BackgroundJobs;

public class DependencyResolutionJob(TemplateDbContext db, PackageResolutionService resolver,
    BackgroundJobRegistry jobs,
    ILogger<DependencyResolutionJob> logger, IConfiguration configuration) : IBackgroundJob
{
    public string Name => "S360 dependency resolution";
    public string Description => "Resolves pending employee requests without running package install scripts.";

    public async Task ExecuteAsync()
    {
        var pendingIds = await db.DependencyApplications.Where(a => a.Status == ApplicationStatus.Resolving)
            .OrderBy(a => a.CreatedAtUtc).Take(10).Select(a => a.Id).ToListAsync();
        foreach (var id in pendingIds)
        {
            var application = await db.DependencyApplications.FirstOrDefaultAsync(a =>
                a.Id == id && a.Status == ApplicationStatus.Resolving);
            if (application == null) continue;
            try
            {
                var direct = JsonSerializer.Deserialize<List<DirectPackage>>(application.DirectPackages)
                    ?? throw new InvalidOperationException("Direct dependencies are missing.");
                var blocksBeforeDownload = await db.BlockRules.AsNoTracking()
                    .Where(b => b.Active && b.Ecosystem == application.Ecosystem).ToListAsync();
                RequestResolutionPolicy.ValidateBeforeDownload(application.Ecosystem, application.Source,
                    direct, configuration, blocksBeforeDownload);
                var report = await resolver.ResolveAsync(application.Ecosystem, application.Source, direct);
                if (!AllowedPackageSources.Contains(configuration, application.Ecosystem, application.Source))
                    throw new InvalidOperationException("Package source was removed while resolving the request.");
                var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active && b.Ecosystem == application.Ecosystem)
                    .ToListAsync();
                foreach (var dependency in report.Dependencies)
                {
                    var block = BlockRulePolicy.Match(blocks, dependency.Ecosystem, dependency.Name, dependency.Version);
                    if (block != null)
                        throw new InvalidOperationException(BlockRulePolicy.Explain(block, dependency.Name,
                            dependency.Version, FindPath(report, dependency)));
                }

                if (await SaveResolutionAsync(id, report))
                    jobs.TriggerNow<VulnerabilityAuditJob>();
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "S360 request {ApplicationId} resolution failed.", id);
                await MarkFailedIfStillResolvingAsync(db, id, ex.Message);
            }
        }
    }

    public async Task<bool> SaveResolutionAsync(int id, ResolutionReport report)
    {
        var strategy = db.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async () =>
        {
            db.ChangeTracker.Clear();
            var application = await db.DependencyApplications.SingleAsync(a => a.Id == id);
            if (application.Status != ApplicationStatus.Resolving) return false;

            await using var transaction = db.Database.IsRelational()
                ? await db.Database.BeginTransactionAsync() : null;

            var map = new Dictionary<string, PackageArtifact>(StringComparer.Ordinal);
            foreach (var dependency in report.Dependencies)
            {
                var source = TrustPattern.NormalizeSource(dependency.Source);
                var key = Key(dependency);
                var identityKey = PackageArtifact.CalculateIdentityKey(dependency.Ecosystem,
                    dependency.Name, dependency.Version, source, dependency.Sha256);
                var artifact = await db.PackageArtifacts.FirstOrDefaultAsync(a => a.IdentityKey == identityKey);
                if (artifact == null)
                {
                    artifact = new PackageArtifact
                    {
                        Ecosystem = dependency.Ecosystem, Name = dependency.Name,
                        Version = dependency.Version, Source = source, Sha256 = dependency.Sha256,
                        SourceVerifiedAtUtc = DateTime.UtcNow
                    };
                    db.PackageArtifacts.Add(artifact);
                }
                else artifact.SourceVerifiedAtUtc ??= DateTime.UtcNow;
                map[key] = artifact;
            }
            await db.SaveChangesAsync();
            var directKeys = report.Edges.Where(e => e.Parent == null)
                .Select(e => Key(e.Child)).ToHashSet(StringComparer.Ordinal);
            application.Packages = report.Dependencies.Select(d => new ApplicationPackage
            {
                PackageArtifactId = map[Key(d)].Id,
                IsDirect = directKeys.Contains(Key(d))
            }).DistinctBy(p => p.PackageArtifactId).ToList();
            application.Edges = report.Edges.Select(e => new ApplicationEdge
            {
                ParentPackageId = e.Parent == null ? null : map[Key(e.Parent)].Id,
                ChildPackageId = map[Key(e.Child)].Id
            }).DistinctBy(e => $"{e.ParentPackageId}/{e.ChildPackageId}").ToList();
            application.ResolutionContext = report.Context;
            application.ReportHash = ReportFingerprint.Compute(application, report);
            application.ResolvedAtUtc = DateTime.UtcNow;
            application.Failure = report.SkippedOptional.Count == 0 ? null :
                "Optional packages absent on this platform: " +
                string.Join("; ", report.SkippedOptional)[..Math.Min(string.Join("; ", report.SkippedOptional).Length, 1800)];
            await db.SaveChangesAsync();
            if (!await MarkReadyIfStillResolvingAsync(db, id))
            {
                if (transaction != null) await transaction.RollbackAsync();
                db.ChangeTracker.Clear();
                return false;
            }
            if (transaction != null) await transaction.CommitAsync();
            db.ChangeTracker.Clear();
            return true;
        });
    }

    public static async Task<bool> MarkReadyIfStillResolvingAsync(TemplateDbContext db, int applicationId)
    {
        if (!db.Database.IsRelational())
        {
            var application = await db.DependencyApplications.FirstOrDefaultAsync(a =>
                a.Id == applicationId && a.Status == ApplicationStatus.Resolving);
            if (application == null) return false;
            application.Status = ApplicationStatus.ReadyForReview;
            await db.SaveChangesAsync();
            return true;
        }
        return await db.DependencyApplications
            .Where(a => a.Id == applicationId && a.Status == ApplicationStatus.Resolving)
            .ExecuteUpdateAsync(setters => setters.SetProperty(a => a.Status, ApplicationStatus.ReadyForReview)) == 1;
    }

    public static async Task<bool> MarkFailedIfStillResolvingAsync(TemplateDbContext db, int applicationId,
        string failure)
    {
        // Do not persist graph entities that were only partially assembled before the exception.
        db.ChangeTracker.Clear();
        var message = failure[..Math.Min(failure.Length, 2000)];
        if (!db.Database.IsRelational())
        {
            var application = await db.DependencyApplications.FirstOrDefaultAsync(a =>
                a.Id == applicationId && a.Status == ApplicationStatus.Resolving);
            if (application == null) return false;
            application.Status = ApplicationStatus.Failed;
            application.Failure = message;
            await db.SaveChangesAsync();
            return true;
        }
        var updated = await db.DependencyApplications
            .Where(a => a.Id == applicationId && a.Status == ApplicationStatus.Resolving)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(a => a.Status, ApplicationStatus.Failed)
                .SetProperty(a => a.Failure, message));
        return updated == 1;
    }

    private static string Key(Dependency d) =>
        $"{d.Ecosystem}\n{(d.Ecosystem == "nuget" ? d.Name.ToLowerInvariant() : d.Name)}\n{d.Version}\n{d.Source}\n{d.Sha256.ToLowerInvariant()}";

    private static string FindPath(ResolutionReport report, Dependency target)
    {
        var paths = new Dictionary<string, string>(StringComparer.Ordinal);
        var queue = new Queue<Dependency>();
        foreach (var edge in report.Edges.Where(e => e.Parent == null))
        {
            paths[Key(edge.Child)] = edge.Child.Name;
            queue.Enqueue(edge.Child);
        }
        while (queue.TryDequeue(out var parent))
        {
            foreach (var edge in report.Edges.Where(e => e.Parent != null && Key(e.Parent) == Key(parent)))
            {
                if (paths.ContainsKey(Key(edge.Child))) continue;
                paths[Key(edge.Child)] = paths[Key(parent)] + " → " + edge.Child.Name;
                queue.Enqueue(edge.Child);
            }
        }
        return paths.GetValueOrDefault(Key(target), target.Name);
    }
}
