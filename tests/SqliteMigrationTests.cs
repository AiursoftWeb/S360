using Aiursoft.S360.Entities;
using Aiursoft.S360.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Aiursoft.S360.Tests;

[TestClass]
public class SqliteMigrationTests
{
    [TestMethod]
    public async Task SupplyChainMigrationsCreateUsableRelationalSchema()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-migration-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>()
                .UseSqlite($"Data Source={file}").Options;
            await using (var db = new SqliteContext(options))
            {
                await db.Database.MigrateAsync();
                var supplier = new Supplier { Name = "Migration test supplier" };
                db.Suppliers.Add(supplier);
                db.TrustRules.Add(new TrustRule
                {
                    ApplicationId = null, SupplierId = supplier.Id,
                    Supplier = supplier, Ecosystem = "nuget", PackagePattern = "Example.*", Version = "1.*",
                    Source = "https://api.nuget.org/v3/index.json", Status = TrustRuleStatus.Approved,
                    Reviews = [new TrustRuleReview
                    {
                        TrustRuleId = 0,
                        Decision = TrustRuleStatus.Approved, ReportHash = new string('b', 64),
                        DecisionBatchId = new string('c', 32)
                    }]
                });
                db.PackageArtifacts.Add(new PackageArtifact
                {
                    Ecosystem = "nuget", Name = "Example.Package", Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64)
                });
                db.BuildChecks.Add(new BuildCheck
                {
                    RunId = Guid.NewGuid().ToString("N"), ScannedProjectCount = 2,
                    Trusted = true
                });
                await db.SaveChangesAsync();
            }
            await using (var db = new SqliteContext(options))
            {
                Assert.AreEqual(1, await db.TrustRules.CountAsync());
                Assert.AreEqual(1, await db.PackageArtifacts.CountAsync());
                var storedArtifact = await db.PackageArtifacts.SingleAsync();
                Assert.AreEqual(64, storedArtifact.IdentityKey.Length);
                var caseVariantKey = PackageArtifact.CalculateIdentityKey("nuget", "example.package",
                    "1.0.0", "https://api.nuget.org/v3/index.json", new string('A', 64));
                Assert.AreEqual(storedArtifact.Id,
                    (await db.PackageArtifacts.SingleAsync(a => a.IdentityKey == caseVariantKey)).Id);
                Assert.AreNotEqual(PackageArtifact.CalculateIdentityKey("npm", "Example.Package",
                    "1.0.0", "https://registry.npmjs.org", new string('a', 64)),
                    PackageArtifact.CalculateIdentityKey("npm", "example.package",
                        "1.0.0", "https://registry.npmjs.org", new string('a', 64)));
                var review = await db.TrustRuleReviews.SingleAsync();
                Assert.AreEqual(new string('b', 64), review.ReportHash);
                Assert.AreEqual(new string('c', 32), review.DecisionBatchId);
                Assert.AreEqual(2, (await db.BuildChecks.SingleAsync()).ScannedProjectCount);
                Assert.AreEqual(0, (await db.Database.GetPendingMigrationsAsync()).Count());
            }
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }

    [TestMethod]
    public async Task AdvisoryRevisionMigrationPreservesExistingCurrentState()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-revision-migration-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            var options = new DbContextOptionsBuilder<SqliteContext>()
                .UseSqlite($"Data Source={file}").Options;
            await using (var db = new SqliteContext(options))
            {
                await db.GetService<IMigrator>().MigrateAsync("20260923132803_RecordScannedProjectCount");
                db.Vulnerabilities.Add(new Vulnerability
                {
                    Ecosystem = "npm", PackageName = "sample", SourceId = "GHSA-test-1111-2222",
                    Aliases = "[\"CVE-2026-0001\"]", Summary = "Original finding", Severity = "HIGH",
                    ModifiedAtUtc = new DateTime(2026, 9, 23, 0, 0, 0, DateTimeKind.Utc),
                    FetchedAtUtc = new DateTime(2026, 9, 23, 1, 0, 0, DateTimeKind.Utc),
                    RawAffectedJson = "[]"
                });
                await db.SaveChangesAsync();
                await db.Database.MigrateAsync();
            }
            await using (var db = new SqliteContext(options))
            {
                var revision = await db.VulnerabilityRevisions.SingleAsync();
                Assert.AreEqual("Original finding", revision.Summary);
                Assert.AreEqual("HIGH", revision.Severity);
                Assert.AreEqual("[]", revision.RawAffectedJson);
                Assert.AreEqual(0, (await db.Database.GetPendingMigrationsAsync()).Count());
            }
        }
        finally
        {
            if (File.Exists(file)) File.Delete(file);
        }
    }
    [TestMethod]
    public async Task CheckContextMigrationPreservesLegacyChecksAsUnclassified()
    {
        var file = Path.Combine(Path.GetTempPath(), "s360-check-context-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            await using var db = new SqliteContext(new DbContextOptionsBuilder<SqliteContext>()
                .UseSqlite($"Data Source={file}").Options);
            await db.GetService<IMigrator>().MigrateAsync("20260923142925_PreserveAdvisoryRevisions");
            await db.Database.ExecuteSqlRawAsync("""
                INSERT INTO BuildChecks (Project, "Commit", Pipeline, RunId, BatchIndex, BatchCount,
                    ScannedProjectCount, CreatedAtUtc, Trusted)
                VALUES ('legacy-project', 'legacy-commit', 'legacy-pipeline',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, 1, 1, '2026-10-17 12:00:00', 0);
                """);
            await db.Database.MigrateAsync();
            var legacy = await db.BuildChecks.SingleAsync();
            Assert.AreEqual("legacy-project", legacy.Project);
            Assert.AreEqual("legacy-commit", legacy.Commit);
            Assert.IsNull(legacy.ContextJson);
            Assert.AreEqual(Services.CheckKind.Unknown, Services.BuildCheckRun.Kind(legacy.ContextJson));
            legacy.ContextJson = "{\"Provider\":\"local\"}";
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
            Assert.AreEqual(Services.CheckKind.Local,
                Services.BuildCheckRun.Kind((await db.BuildChecks.SingleAsync()).ContextJson));
        }
        finally { if (File.Exists(file)) File.Delete(file); }
    }
}
