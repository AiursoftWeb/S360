using Aiursoft.S360.Entities;
using Aiursoft.S360.MySql;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.S360.Sqlite;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;

namespace Aiursoft.S360.Tests;

[TestClass]
public class RiskAcceptancePersistenceTests
{
    [TestMethod]
    [DataRow("sqlite")]
    [DataRow("mysql")]
    public async Task ExistingSchemaPersistsRiskAcceptanceAndItsDecisionHistory(string provider)
    {
        var name = "s360_risk_" + Guid.NewGuid().ToString("N");
        TemplateDbContext db;
        if (provider == "mysql")
        {
            var connection = Environment.GetEnvironmentVariable("S360_TEST_MYSQL");
            if (string.IsNullOrWhiteSpace(connection)) Assert.Inconclusive("Set S360_TEST_MYSQL to an isolated test server.");
            var builder = new MySqlConnectionStringBuilder(connection) { Database = name };
            db = new MySqlContext(new DbContextOptionsBuilder<MySqlContext>().UseMySql(builder.ConnectionString,
                new MySqlServerVersion(new Version(9, 7, 0))).Options);
        }
        else db = new SqliteContext(new DbContextOptionsBuilder<SqliteContext>()
            .UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), name + ".db")}").Options);
        await using (db)
        {
            try
            {
                await db.Database.MigrateAsync();
                var advisory = RiskAcceptancePolicyTests.Advisory(0);
                db.Vulnerabilities.Add(advisory);
                await db.SaveChangesAsync();
                var rule = RiskAcceptancePolicyTests.Acceptance();
                rule.VulnerabilityId = advisory.Id;
                rule.ExpiresAtUtc = new DateTime(rule.ExpiresAtUtc!.Value.Ticks / 10 * 10, DateTimeKind.Utc);
                db.Rules.Add(rule);
                db.RuleChanges.Add(new RuleChange { Rule = rule, Decision = RuleStatus.Approved,
                    ReviewerId = "reviewer", Reason = "Documented applicability assessment.", ExpiresAtUtc = rule.ExpiresAtUtc });
                await db.SaveChangesAsync();
                db.ChangeTracker.Clear();
                var saved = await db.Rules.Include(r => r.Reviews).SingleAsync();
                Assert.AreEqual(RuleKind.RiskAcceptance, saved.Kind);
                Assert.AreEqual("reviewer", saved.Reviews.Single().ReviewerId);
                Assert.AreEqual(rule.ExpiresAtUtc, saved.ExpiresAtUtc);
                var policy = await VulnerabilityPolicy.LoadAsync(db, DateTime.UtcNow);
                var result = policy.Assess(new SDK.Dependency { Ecosystem = "npm", Name = "picomatch",
                    Version = "4.0.7", Source = saved.Source });
                Assert.HasCount(1, result.Accepted);
                Assert.HasCount(0, result.Blocking);
            }
            finally { await db.Database.EnsureDeletedAsync(); }
        }
    }
}
