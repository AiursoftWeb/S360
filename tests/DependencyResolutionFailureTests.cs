using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Resolution;
using Microsoft.Extensions.Logging.Abstractions;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests;

[TestClass]
public class DependencyResolutionFailureTests
{
    [TestMethod]
    public async Task IndependentlyResolvedArchiveClearsPriorSourceRejectionButStillRequiresAudit()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-source-recovery-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var dependency = new Dependency { Ecosystem = "npm", Name = "sample", Version = "1.0.0",
            Source = "https://registry.npmjs.org", Sha256 = new string('a', 64) };
        var application = new DependencyApplication { RequestedByUserId = "employee", Ecosystem = "npm",
            Source = dependency.Source, Justification = "Reverify the source", ResolutionContext = "npm",
            DirectPackages = """[{"Name":"sample","Version":"1.0.0"}]""", Status = ApplicationStatus.Resolving };
        db.DependencyApplications.Add(application);
        db.TrustRules.Add(new TrustRule { SupplierId = 0, ApplicationId = null, Ecosystem = "npm",
            PackagePattern = "sample", Version = "1.*", Source = dependency.Source, Status = TrustRuleStatus.Approved });
        db.PackageArtifacts.Add(new PackageArtifact { Ecosystem = dependency.Ecosystem, Name = dependency.Name,
            Version = dependency.Version, Source = dependency.Source, Sha256 = dependency.Sha256,
            SourceVerificationRejected = true });
        await db.SaveChangesAsync();
        var job = new DependencyResolutionJob(db, null!, null!, NullLogger<DependencyResolutionJob>.Instance, null!);
        Assert.IsTrue(await job.SaveResolutionAsync(application.Id,
            new ResolutionReport([dependency], [new ResolutionEdge(null, dependency)], [], "npm")));
        var artifact = await db.PackageArtifacts.SingleAsync();
        Assert.IsFalse(artifact.SourceVerificationRejected);
        Assert.IsNotNull(artifact.SourceVerifiedAtUtc);
        Assert.IsNull(artifact.LastCheckedAtUtc);
        Assert.IsNull(artifact.FirstTrustedAtUtc);
        var decision = (await new TrustService(db).AssessAsync([dependency])).Single();
        Assert.IsFalse(decision.Trusted);
        Assert.IsTrue(decision.PendingVerification);
    }

    [TestMethod]
    public async Task InMemoryTestProviderAlsoRecordsResolutionFailure()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-resolution-failure-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var application = new DependencyApplication
        {
            RequestedByUserId = "employee", Ecosystem = "npm", Source = "https://registry.npmjs.org",
            Justification = "Evaluate a dependency", DirectPackages = "[]", ResolutionContext = "npm",
            Status = ApplicationStatus.Resolving
        };
        db.DependencyApplications.Add(application);
        await db.SaveChangesAsync();
        Assert.IsTrue(await DependencyResolutionJob.MarkFailedIfStillResolvingAsync(db, application.Id, "resolve failed"));
        Assert.AreEqual(ApplicationStatus.Failed, (await db.DependencyApplications.SingleAsync()).Status);
    }

    [TestMethod]
    public async Task FailedResolutionCannotOverwriteWithdrawalOrSavePartialGraph()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-resolution-failure-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite($"Data Source={file}").Options;
            await using var worker = new SqliteContext(options);
            await worker.Database.MigrateAsync();
            var application = new DependencyApplication
            {
                RequestedByUserId = "employee", Ecosystem = "nuget", Source = "https://api.nuget.org/v3/index.json",
                Justification = "Evaluate a dependency", DirectPackages = "[]", ResolutionContext = "net10.0",
                Status = ApplicationStatus.Resolving
            };
            worker.DependencyApplications.Add(application);
            await worker.SaveChangesAsync();
            worker.PackageArtifacts.Add(new PackageArtifact
            {
                Ecosystem = "nuget", Name = "partial", Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64)
            });
            await using (var employee = new SqliteContext(options))
            {
                var withdrawn = await employee.DependencyApplications.SingleAsync();
                withdrawn.Status = ApplicationStatus.Withdrawn;
                await employee.SaveChangesAsync();
            }
            Assert.IsFalse(await DependencyResolutionJob.MarkFailedIfStillResolvingAsync(worker, application.Id, "resolve failed"));
            await using var verify = new SqliteContext(options);
            Assert.AreEqual(ApplicationStatus.Withdrawn, (await verify.DependencyApplications.SingleAsync()).Status);
            Assert.AreEqual(0, await verify.PackageArtifacts.CountAsync());
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }

    [TestMethod]
    public async Task FailedResolutionRecordsErrorOnlyWhileStillResolving()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-resolution-failure-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite($"Data Source={file}").Options;
            await using var db = new SqliteContext(options);
            await db.Database.MigrateAsync();
            var application = new DependencyApplication
            {
                RequestedByUserId = "employee", Ecosystem = "npm", Source = "https://registry.npmjs.org",
                Justification = "Evaluate a dependency", DirectPackages = "[]", ResolutionContext = "npm",
                Status = ApplicationStatus.Resolving
            };
            db.DependencyApplications.Add(application);
            await db.SaveChangesAsync();
            Assert.IsTrue(await DependencyResolutionJob.MarkFailedIfStillResolvingAsync(db, application.Id, new string('x', 2200)));
            await using var verify = new SqliteContext(options);
            var failed = await verify.DependencyApplications.SingleAsync();
            Assert.AreEqual(ApplicationStatus.Failed, failed.Status);
            Assert.AreEqual(2000, failed.Failure?.Length);
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }

    [TestMethod]
    public async Task WithdrawnApplicationCannotCommitResolvedArtifactsOrBecomeReady()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-resolution-race-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite($"Data Source={file}").Options;
            await using var worker = new SqliteContext(options);
            await worker.Database.MigrateAsync();
            var application = new DependencyApplication
            {
                RequestedByUserId = "employee", Ecosystem = "nuget", Source = "https://api.nuget.org/v3/index.json",
                Justification = "Evaluate a dependency", DirectPackages = "[]", ResolutionContext = "net10.0",
                Status = ApplicationStatus.Resolving
            };
            worker.DependencyApplications.Add(application);
            await worker.SaveChangesAsync();
            await using (var employee = new SqliteContext(options))
            {
                var withdrawal = await employee.DependencyApplications.SingleAsync();
                withdrawal.Status = ApplicationStatus.Withdrawn;
                await employee.SaveChangesAsync();
            }
            await using (var transaction = await worker.Database.BeginTransactionAsync())
            {
                worker.PackageArtifacts.Add(new PackageArtifact
                {
                    Ecosystem = "nuget", Name = "uncommitted", Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64)
                });
                await worker.SaveChangesAsync();
                Assert.IsFalse(await DependencyResolutionJob.MarkReadyIfStillResolvingAsync(worker, application.Id));
                await transaction.RollbackAsync();
            }
            await using var verify = new SqliteContext(options);
            Assert.AreEqual(ApplicationStatus.Withdrawn, (await verify.DependencyApplications.SingleAsync()).Status);
            Assert.AreEqual(0, await verify.PackageArtifacts.CountAsync());
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }

    [TestMethod]
    public async Task ResolvedApplicationAndArtifactsCommitTogether()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-resolution-ready-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite($"Data Source={file}").Options;
            await using var worker = new SqliteContext(options);
            await worker.Database.MigrateAsync();
            var application = new DependencyApplication
            {
                RequestedByUserId = "employee", Ecosystem = "nuget", Source = "https://api.nuget.org/v3/index.json",
                Justification = "Evaluate a dependency", DirectPackages = "[]", ResolutionContext = "net10.0",
                Status = ApplicationStatus.Resolving
            };
            worker.DependencyApplications.Add(application);
            await worker.SaveChangesAsync();
            await using (var transaction = await worker.Database.BeginTransactionAsync())
            {
                worker.PackageArtifacts.Add(new PackageArtifact
                {
                    Ecosystem = "nuget", Name = "committed", Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64)
                });
                await worker.SaveChangesAsync();
                Assert.IsTrue(await DependencyResolutionJob.MarkReadyIfStillResolvingAsync(worker, application.Id));
                await transaction.CommitAsync();
            }
            await using var verify = new SqliteContext(options);
            Assert.AreEqual(ApplicationStatus.ReadyForReview, (await verify.DependencyApplications.SingleAsync()).Status);
            Assert.AreEqual(1, await verify.PackageArtifacts.CountAsync());
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }
}
