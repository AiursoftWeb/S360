using System.Data.Common;
using Aiursoft.S360.Entities;
using Aiursoft.S360.MySql;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using MySqlConnector;

namespace Aiursoft.S360.Tests;

[TestClass]
public class AdmissionQueryTests
{
    private const string Source = "https://registry.npmjs.org";

    [TestMethod]
    [DataRow("sqlite")]
    [DataRow("mysql")]
    public async Task OnlyAuthorizedPackagesLoadAdvisoriesAndDetailsReuseTheResult(string provider)
    {
        var reads = new PolicyReads();
        await using var db = CreateDatabase(provider, reads);
        try
        {
            await db.Database.EnsureCreatedAsync();
            db.Rules.Add(Approval("picomatch"));
            db.Vulnerabilities.Add(RiskAcceptancePolicyTests.Advisory());
            AddFreshAudit(db);
            await db.SaveChangesAsync();
            reads.Commands.Clear();
            var trust = new TrustService(db);

            Assert.HasCount(0, await trust.AssessAsync([]));
            Assert.HasCount(0, reads.Commands);
            Assert.IsFalse((await trust.AssessAsync([Package("PICOMATCH")])).Single().Trusted);
            Assert.HasCount(0, reads.AdvisoryBodies);

            reads.Commands.Clear();
            var dependencies = new[] { Package("unapproved"), Package("picomatch") };
            var decisions = await trust.AssessAsync(dependencies);
            Assert.AreEqual("No approved trust rule.", decisions[0].Reason);
            StringAssert.Contains(decisions[1].Reason, "GHSA-test");
            var advisoryQuery = reads.AdvisoryBodies.Single();
            StringAssert.Contains(advisoryQuery.Sql, "WHERE");
            StringAssert.Contains(advisoryQuery.Sql + advisoryQuery.Parameters, "picomatch");
            Assert.IsFalse((advisoryQuery.Sql + advisoryQuery.Parameters).Contains("unapproved", StringComparison.Ordinal));
            Assert.IsFalse(advisoryQuery.Sql.Contains("Summary", StringComparison.Ordinal));
            Assert.IsTrue(reads.Commands.Any(c => c.Sql.Contains("FROM Rules", StringComparison.Ordinal) &&
                c.Sql.Contains("PackagePattern", StringComparison.Ordinal) &&
                !c.Sql.Contains("Justification", StringComparison.Ordinal)));

            reads.Commands.Clear();
            var states = await new PackageStatusService(trust, new ConfigurationBuilder().Build()).DescribeAsync(dependencies);
            Assert.AreEqual(decisions[1].Reason, states[1].Admission.Reason);
            Assert.IsTrue(states[1].Authorization.Trusted);
            Assert.HasCount(1, states[1].BlockingAdvisories);
            Assert.HasCount(1, reads.AdvisoryBodies);
        }
        finally { await db.Database.EnsureDeletedAsync(); }
    }

    [TestMethod]
    [DataRow("sqlite")]
    [DataRow("mysql")]
    public async Task AVersionLinkRetainsCrossPackageRangesAndWithdrawnAliasChains(string provider)
    {
        await using var db = CreateDatabase(provider, new PolicyReads());
        try
        {
            await db.Database.EnsureCreatedAsync();
            var affected = RiskAcceptancePolicyTests.Advisory(1, "GHSA-linked", "[\"CVE-2099-1111\"]");
            var bridge = RiskAcceptancePolicyTests.Advisory(2, "CVE-2099-1111");
            var acceptedAdvisory = RiskAcceptancePolicyTests.Advisory(3, "CVE-2099-1234", "[]");
            foreach (var advisory in new[] { affected, bridge, acceptedAdvisory }) advisory.PackageName = "original-package";
            bridge.Withdrawn = true;
            acceptedAdvisory.Withdrawn = true;
            db.Vulnerabilities.AddRange(affected, bridge, acceptedAdvisory);
            db.VulnerabilityMatches.Add(new VulnerabilityMatch
            {
                VulnerabilityId = affected.Id, Vulnerability = affected, PackageVersionId = 1,
                PackageVersion = new PackageVersion { Id = 1, Ecosystem = "npm", Name = "picomatch", Version = "4.0.7", Source = Source }
            });
            var acceptance = RiskAcceptancePolicyTests.Acceptance();
            acceptance.VulnerabilityId = acceptedAdvisory.Id;
            acceptance.Vulnerability = acceptedAdvisory;
            db.Rules.AddRange(Approval("picomatch"), acceptance);
            AddFreshAudit(db);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();

            var trust = new TrustService(db);
            var accepted = (await trust.AssessAsync([Package("picomatch")])).Single();
            Assert.IsTrue(accepted.Trusted, accepted.Reason);
            StringAssert.Contains(accepted.Reason, "risk accepted");
            var earlierVersion = (await trust.AssessAsync([Package("picomatch", "4.0.6")])).Single();
            Assert.IsFalse(earlierVersion.Trusted);
            StringAssert.Contains(earlierVersion.Reason, "GHSA-linked");
        }
        finally { await db.Database.EnsureDeletedAsync(); }
    }

    private static Dependency Package(string name, string version = "4.0.7") =>
        new() { Ecosystem = "npm", Name = name, Version = version, Source = Source };

    private static PackageRule Approval(string name) => new()
    {
        Ecosystem = "npm", PackagePattern = name, Source = Source, Status = RuleStatus.Approved,
        RequestedAtUtc = DateTime.UtcNow.AddDays(-1), Justification = "Visible in package history."
    };

    private static void AddFreshAudit(TemplateDbContext db) => db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
    {
        LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2), LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-1)
    });

    private static TemplateDbContext CreateDatabase(string provider, PolicyReads reads)
    {
        var name = "s360_admission_" + Guid.NewGuid().ToString("N");
        if (provider == "sqlite") return new SqliteContext(new DbContextOptionsBuilder<SqliteContext>()
            .UseSqlite($"Data Source={Path.Combine(Path.GetTempPath(), name + ".db")}").AddInterceptors(reads).Options);
        var connection = Environment.GetEnvironmentVariable("S360_TEST_MYSQL");
        if (string.IsNullOrWhiteSpace(connection)) Assert.Inconclusive("Set S360_TEST_MYSQL to an isolated test server.");
        var builder = new MySqlConnectionStringBuilder(connection) { Database = name };
        return new MySqlContext(new DbContextOptionsBuilder<MySqlContext>().UseMySql(builder.ConnectionString,
            new MySqlServerVersion(new Version(9, 7, 0)), options => options.EnableRetryOnFailure())
            .AddInterceptors(reads).Options);
    }

    private sealed class PolicyReads : DbCommandInterceptor
    {
        public List<(string Sql, string Parameters)> Commands { get; } = [];
        public List<(string Sql, string Parameters)> AdvisoryBodies => Commands.Where(command =>
            command.Sql.Contains("FROM Vulnerabilities", StringComparison.Ordinal) &&
            command.Sql.Contains("RawAffectedJson", StringComparison.Ordinal)).ToList();

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Commands.Add((command.CommandText.Replace("`", "").Replace("\"", ""),
                string.Join(" ", command.Parameters.Cast<DbParameter>().Select(parameter => parameter.Value))));
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }
    }
}
