using Aiursoft.S360.Entities;
using Aiursoft.S360.MySql;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Sqlite;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using MySqlConnector;

namespace Aiursoft.S360.Tests;

[TestClass]
public class SchemaSimplificationTests
{
    [TestMethod]
    [DataRow("sqlite")]
    [DataRow("mysql")]
    public async Task UpgradePreservesDecisionsHistoryAndVulnerabilityLinks(string provider)
    {
        await using var sqlite = new SqliteConnection("Data Source=:memory:");
        TemplateDbContext db;
        if (provider == "sqlite")
        {
            await sqlite.OpenAsync();
            db = new SqliteContext(new DbContextOptionsBuilder<SqliteContext>().UseSqlite(sqlite).Options);
        }
        else
        {
            var connection = Environment.GetEnvironmentVariable("S360_TEST_MYSQL");
            if (string.IsNullOrWhiteSpace(connection)) Assert.Inconclusive("Set S360_TEST_MYSQL to an isolated test server.");
            var builder = new MySqlConnectionStringBuilder(connection) { Database = "s360_schema_" + Guid.NewGuid().ToString("N") };
            db = new MySqlContext(new DbContextOptionsBuilder<MySqlContext>()
                .UseMySql(builder.ConnectionString, new MySqlServerVersion(new Version(9, 7, 0))).Options);
        }
        await using (db)
        {
            try
            {
                var previous = db.Database.GetMigrations().Last(m => !m.EndsWith("_SimplifyComplianceRules", StringComparison.Ordinal));
                await db.GetService<IMigrator>().MigrateAsync(previous);
                // Insert historical schema directly. The new entities must never write old tables.
                await db.Database.ExecuteSqlRawAsync("""
                    INSERT INTO DependencyApplications (Id,RequestedByUserId,Justification,Ecosystem,Source,DirectPackages,ResolutionContext,Status,CreatedAtUtc)
                    VALUES (1,'requester','Original request','nuget','https://registry.example','[]','Historical request',3,'2026-01-01 00:00:00');
                    INSERT INTO Suppliers (Id,Name) VALUES (1,'Historical publisher');
                    INSERT INTO PackagePolicies (Id,Ecosystem,Name,NormalizedName,Source,IdentityKey)
                    VALUES (1,'nuget','Example','example','https://registry.example','old-policy-key');
                    INSERT INTO TrustRules (Id,SupplierId,ApplicationId,Ecosystem,PackagePattern,Version,Source,Sha256,
                      IncludePrerelease,Justification,RequestedByUserId,RequestedAtUtc,ExpiresAtUtc,Status,PackagePolicyId,LegacySourceRuleId)
                    VALUES (1,1,NULL,'nuget','Example','*','https://registry.example','obsolete-proof',0,'Allowed','requester','2026-01-01 00:00:00',NULL,1,1,NULL),
                      (2,NULL,NULL,'nuget','Example','2.*','https://registry.example',NULL,0,'Rejected','requester','2026-01-01 00:00:00',NULL,2,1,NULL),
                      (3,NULL,NULL,'nuget','Example','3.*','https://registry.example',NULL,0,'Revoked','requester','2026-01-01 00:00:00',NULL,3,1,NULL),
                      (4,NULL,NULL,'nuget','Legacy.*','*','https://registry.example',NULL,0,'Old denial','requester','2026-01-01 00:00:00',NULL,2,NULL,NULL);
                    INSERT INTO BlockRules (Id,Ecosystem,PackagePattern,Version,Reason,Active,CreatedAtUtc,CreatedByUserId)
                    VALUES (1,'nuget','Example','4.*','Global incident',1,'2026-01-01 00:00:00','security'),
                      (2,'nuget','Example','5.*','Disabled block',0,'2026-01-01 00:00:00','security');
                    INSERT INTO TrustRuleReviews (Id,TrustRuleId,Decision,ReviewerId,Reason,ReportHash,DecisionBatchId,ReviewedAtUtc,ExpiresAtUtc)
                    VALUES (1,1,1,'reviewer','Approved original request','review-fingerprint','batch','2026-01-01 00:00:00',NULL),
                      (2,2,2,'reviewer','Explicit refusal',NULL,NULL,'2026-01-01 00:00:00',NULL);
                    INSERT INTO BlockRuleChanges (Id,BlockRuleId,ChangedByUserId,Description,ChangedAtUtc)
                    VALUES (1,1,'security','Created: global incident','2026-01-01 00:00:00'),
                      (2,2,'security','Disabled: recovered','2026-01-02 00:00:00');
                    INSERT INTO PackageArtifacts (Id,Ecosystem,Name,Version,Source,IdentityKey,Sha256,FirstSeenAtUtc,
                      FirstTrustedAtUtc,LastCheckedAtUtc,SourceVerifiedAtUtc,SourceVerificationRejected,IndependentCheckAtUtc,VerificationSource)
                    VALUES (1,'nuget','Example','1.0.0','https://registry.example','old-file-key','old-file-hash','2026-01-01 00:00:00',NULL,NULL,NULL,1,NULL,NULL);
                    INSERT INTO ApplicationPackages (Id,ApplicationId,PackageArtifactId,IsDirect) VALUES (1,1,1,1);
                    INSERT INTO BuildChecks (Id,Project,CreatedAtUtc,Trusted,RunId,BatchIndex,BatchCount,ScannedProjectCount)
                    VALUES (1,'Original project','2026-01-01 00:00:00',1,'original-run',0,1,1);
                    INSERT INTO BuildCheckDependencies (Id,BuildCheckId,PackageArtifactId,Ecosystem,Name,Version,Source,Sha256,Trusted,Reason)
                    VALUES (1,1,1,'nuget','Example','1.0.0','https://registry.example','old-file-hash',1,'Original decision');
                    INSERT INTO Vulnerabilities (Id,SourceId,Aliases,Ecosystem,PackageName,Summary,Severity,Url,Withdrawn,ModifiedAtUtc,FetchedAtUtc,RawAffectedJson)
                    VALUES (1,'GHSA-example','[]','nuget','Example','Historical finding','HIGH',NULL,0,'2026-01-01 00:00:00','2026-01-01 00:00:00',{0});
                    INSERT INTO VulnerabilityMatches (Id,VulnerabilityId,PackageArtifactId,Active,FirstSeenAtUtc,LastSeenAtUtc)
                    VALUES (1,1,1,1,'2026-01-01 00:00:00','2026-01-02 00:00:00');
                    INSERT INTO TrustRuleVulnerabilityExclusions (Id,TrustRuleId,VulnerabilityId,CreatedByUserId,Reason,CreatedAtUtc)
                    VALUES (1,1,1,'security','Exclude affected versions','2026-01-02 00:00:00');
                    """, """[{"package":{"ecosystem":"NuGet","name":"Example"},"versions":["1.5.0"]}]""");
                await db.Database.MigrateAsync();
                var rules = await db.Rules.Include(r => r.Vulnerability).ToListAsync();
                Assert.HasCount(7, rules);
                Assert.AreEqual(4, rules.Count(r => r.Kind == RuleKind.Approval));
                Assert.AreEqual(2, rules.Count(r => r.Kind == RuleKind.Block));
                var exclusion = rules.Single(r => r.Kind == RuleKind.VulnerabilityExclusion);
                Assert.AreEqual(1, exclusion.ParentRuleId);
                Assert.AreEqual(1, exclusion.VulnerabilityId);
                Assert.AreEqual("security", exclusion.RequestedByUserId);
                var changes = await db.RuleChanges.OrderBy(c => c.Id).ToListAsync();
                Assert.HasCount(4, changes);
                Assert.AreEqual("review-fingerprint", changes[0].ReportHash);
                Assert.AreEqual("batch", changes[0].DecisionBatchId);
                Assert.AreEqual("Explicit refusal", changes[1].Reason);
                Assert.AreEqual("Created: global incident", changes[2].Reason);
                Assert.AreEqual(rules.Single(r => r.Kind == RuleKind.Block && r.Version == "4.*").Id, changes[2].RuleId);
                Assert.IsNull(changes[2].Decision, "Do not invent a structured decision for an old prose-only change.");
                var match = await db.VulnerabilityMatches.Include(m => m.PackageVersion).SingleAsync();
                Assert.AreEqual(1, match.Id);
                Assert.AreEqual("Example", match.PackageVersion.Name);
                Assert.AreEqual(new DateTime(2026, 1, 2), match.LastSeenAtUtc);
                foreach (var (version, allowed) in new[] { ("1.0.0", true), ("1.5.0", false), ("2.0.0", false), ("3.0.0", false), ("4.0.0", false), ("5.0.0", true), ("6.0.0-preview.1", false) })
                {
                    var result = TrustService.Evaluate(new Dependency { Ecosystem = "nuget", Name = "Example", Version = version, Source = "https://registry.example" },
                        rules.Where(r => r.Kind == RuleKind.Approval), rules.Where(r => r.Kind == RuleKind.Block), DateTime.UtcNow,
                        rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).ToList());
                    Assert.AreEqual(allowed, result.Trusted, version);
                }
                var legacyDenial = TrustService.Evaluate(new Dependency { Ecosystem = "nuget", Name = "Legacy.Child", Version = "1.0.0", Source = "https://registry.example" },
                    rules.Where(r => r.Kind == RuleKind.Approval), [], DateTime.UtcNow);
                Assert.IsFalse(legacyDenial.Trusted);
                Assert.AreEqual(4, legacyDenial.RuleId);
                Assert.IsFalse(db.Model.GetEntityTypes().SelectMany(e => e.GetProperties()).Any(p => p.Name is "Sha256" or "VerificationSource" or "SourceVerifiedAtUtc"));
                var applicationPackage = await db.ApplicationPackages.Include(p => p.Application).SingleAsync();
                Assert.AreEqual(1, applicationPackage.PackageVersionId);
                Assert.IsTrue(applicationPackage.IsDirect);
                Assert.AreEqual("Original request", applicationPackage.Application.Justification);
                var buildPackage = await db.BuildCheckDependencies.Include(p => p.BuildCheck).SingleAsync();
                Assert.AreEqual(1, buildPackage.PackageVersionId);
                Assert.AreEqual("Original decision", buildPackage.Reason);
                Assert.AreEqual("Original project", buildPackage.BuildCheck.Project);
                Assert.IsFalse(db.Database.HasPendingModelChanges());
                if (provider == "sqlite")
                {
                    await using var command = sqlite.CreateCommand();
                    command.CommandText = "PRAGMA foreign_keys;";
                    Assert.AreEqual(1L, await command.ExecuteScalarAsync());
                    command.CommandText = "PRAGMA foreign_key_check;";
                    Assert.IsNull(await command.ExecuteScalarAsync());
                }
            }
            finally { await db.Database.EnsureDeletedAsync(); }
        }
    }
}
