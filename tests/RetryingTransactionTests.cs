using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Services.Resolution;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.S360.Sqlite;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using System.Net;

namespace Aiursoft.S360.Tests;

[TestClass]
public class RetryingTransactionTests
{
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ResolutionCommitsOneCompleteGraphWithRetryingStrategy(bool failOnce)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var failure = new GraphFailure { Enabled = failOnce };
        var options = Options(connection, failure);
        await using var db = new SqliteContext(options);
        await db.Database.EnsureCreatedAsync();
        var application = new DependencyApplication
        {
            RequestedByUserId = "employee", Ecosystem = "npm", Source = "https://registry.npmjs.org",
            Justification = "Test", DirectPackages = """[{"Name":"sample","Version":"1.0.0"}]""", ResolutionContext = "npm", Status = ApplicationStatus.Resolving
        };
        db.DependencyApplications.Add(application);
        await db.SaveChangesAsync();
        var dependency = new Dependency { Ecosystem = "npm", Name = "sample", Version = "1.0.0",
            Source = "https://registry.npmjs.org", Sha256 = new string('a', 64) };
        var report = new ResolutionReport([dependency], [new ResolutionEdge(null, dependency)], [], "npm");
        var job = new DependencyResolutionJob(db, null!, null!, NullLogger<DependencyResolutionJob>.Instance, null!);
        Assert.IsTrue(await job.SaveResolutionAsync(application.Id, report));
        db.ChangeTracker.Clear();
        Assert.AreEqual(ApplicationStatus.ReadyForReview, (await db.DependencyApplications.SingleAsync()).Status);
        Assert.AreEqual(1, await db.PackageArtifacts.CountAsync());
        Assert.AreEqual(1, await db.ApplicationPackages.CountAsync());
        Assert.AreEqual(1, await db.ApplicationEdges.CountAsync());
        Assert.AreEqual(failOnce, failure.Thrown);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task AuditCommitsOneRevisionAndMatchWithRetryingStrategy(bool failOnce)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var failure = new GraphFailure { Enabled = failOnce };
        await using var db = new SqliteContext(Options(connection, failure));
        await db.Database.EnsureCreatedAsync();
        db.PackageArtifacts.Add(new PackageArtifact { Ecosystem = "npm", Name = "sample", Version = "1.0.0",
            Source = "https://registry.npmjs.org", Sha256 = new string('a', 64), SourceVerifiedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        using var handler = new AdvisoryHandler();
        using var http = new HttpClient(handler);
        var job = new VulnerabilityAuditJob(db, new OsvClient(http), new OsvWildcardFeed(http),
            new AcceptingVerifier(), NullLogger<VulnerabilityAuditJob>.Instance);
        await job.ExecuteAsync();
        db.ChangeTracker.Clear();
        Assert.AreEqual(1, await db.Vulnerabilities.CountAsync());
        Assert.AreEqual(1, await db.VulnerabilityRevisions.CountAsync());
        Assert.AreEqual(1, await db.VulnerabilityMatches.CountAsync());
        Assert.IsNotNull((await db.VulnerabilitySyncStates.SingleAsync()).LastSuccessAtUtc);
        Assert.AreEqual(failOnce, failure.Thrown);
        Assert.AreEqual(2, handler.Calls, "Database retries must not repeat network queries.");
    }

    private static DbContextOptions<SqliteContext> Options(SqliteConnection connection, GraphFailure failure) =>
        new DbContextOptionsBuilder<SqliteContext>().UseSqlite(connection)
            .ReplaceService<IExecutionStrategyFactory, RetryFactory>().AddInterceptors(failure).Options;

    public sealed class RetryFactory(ExecutionStrategyDependencies dependencies) : IExecutionStrategyFactory
    {
        public IExecutionStrategy Create() => new RetryStrategy(dependencies);
    }
    private sealed class RetryStrategy(ExecutionStrategyDependencies dependencies)
        : ExecutionStrategy(dependencies, 1, TimeSpan.Zero)
    {
        protected override bool ShouldRetryOn(Exception exception) => exception is RetryFailure;
    }
    private sealed class RetryFailure : Exception;
    private sealed class GraphFailure : SaveChangesInterceptor
    {
        public bool Enabled { get; init; }
        public bool Thrown { get; private set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            var db = eventData.Context!;
            if (Enabled && !Thrown && (db.ChangeTracker.Entries<ApplicationPackage>().Any(e => e.State == EntityState.Added) ||
                db.ChangeTracker.Entries<VulnerabilityMatch>().Any(e => e.State == EntityState.Added)))
            {
                Thrown = true;
                throw new RetryFailure();
            }
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }
    private sealed class AcceptingVerifier : IArtifactSourceVerifier
    {
        public Task<bool> VerifyAsync(PackageArtifact artifact, CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
    private sealed class AdvisoryHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                """{"vulns":[{"id":"TEST-1","modified":"2026-09-23T00:00:00Z","affected":[]}]}""") });
        }
    }
}
