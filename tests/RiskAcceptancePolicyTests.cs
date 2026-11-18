using Aiursoft.S360.Entities;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Vulnerability;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests;

[TestClass]
public class RiskAcceptancePolicyTests
{
    private const string Source = "https://registry.npmjs.org";
    private static Dependency Package(string version = "4.0.7", string source = Source, string name = "picomatch") =>
        new() { Ecosystem = "npm", Name = name, Version = version, Source = source };

    internal static Vulnerability Advisory(int id = 1, string sourceId = "GHSA-test", string aliases = "[\"CVE-2099-1234\"]") =>
        new()
        {
            Id = id, Ecosystem = "npm", PackageName = "picomatch", SourceId = sourceId, Aliases = aliases,
            RawAffectedJson = """
                [{"package":{"ecosystem":"npm","name":"picomatch"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"4.0.7"}]}]}]
                """
        };

    internal static PackageRule Acceptance() => new()
    {
        Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "npm", PackagePattern = "picomatch",
        Version = "4.0.7", Source = Source, VulnerabilityId = 1, Justification = "Only trusted build patterns are used.",
        RequestedAtUtc = DateTime.UtcNow.AddHours(-1), ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
    };

    [TestMethod]
    public void CorrelatedRecordsRemainVisibleWhileOnlyAcceptedRiskStopsBlocking()
    {
        var policy = new VulnerabilityPolicy([Advisory(), Advisory(2, "CVE-2099-1234", "[]")], [Acceptance()], DateTime.UtcNow);
        var result = policy.Assess(Package());
        Assert.HasCount(2, result.Findings);
        Assert.HasCount(2, result.Accepted);
        Assert.HasCount(0, result.Blocking);
    }

    [TestMethod]
    public void AnotherCveStillBlocksTheSameVersion()
    {
        var policy = new VulnerabilityPolicy([Advisory(), Advisory(2, "GHSA-other", "[\"CVE-2099-9999\"]")],
            [Acceptance()], DateTime.UtcNow);
        Assert.AreEqual("GHSA-other", policy.Assess(Package()).Blocking.Single().SourceId);
    }

    [TestMethod]
    [DataRow("pending")]
    [DataRow("rejected")]
    [DataRow("revoked")]
    [DataRow("expired")]
    [DataRow("permanent")]
    [DataRow("source")]
    [DataRow("version")]
    [DataRow("package")]
    [DataRow("ecosystem")]
    [DataRow("application")]
    [DataRow("parent")]
    [DataRow("wrong-advisory")]
    public void AnExceptionOnlyAppliesInsideItsExplicitApprovedScope(string condition)
    {
        var rule = Acceptance();
        switch (condition)
        {
            case "pending": rule.Status = RuleStatus.Pending; break;
            case "rejected": rule.Status = RuleStatus.Rejected; break;
            case "revoked": rule.Status = RuleStatus.Revoked; break;
            case "expired": rule.ExpiresAtUtc = DateTime.UtcNow; break;
            case "permanent": rule.ExpiresAtUtc = null; break;
            case "source": rule.Source = "https://different.example"; break;
            case "version": rule.Version = "4.0.6"; break;
            case "package": rule.PackagePattern = "pico*"; break;
            case "ecosystem": rule.Ecosystem = "nuget"; break;
            case "application": rule.ApplicationId = 1; break;
            case "parent": rule.ParentRuleId = 1; break;
            case "wrong-advisory": rule.VulnerabilityId = 99; break;
        }
        Assert.HasCount(1, new VulnerabilityPolicy([Advisory()], [rule], DateTime.UtcNow).Assess(Package()).Blocking);
    }

    [TestMethod]
    public void UnknownAffectedRangeIsNeverSilentlyAccepted()
    {
        var advisory = Advisory();
        advisory.RawAffectedJson = "not-json";
        var result = new VulnerabilityPolicy([advisory], [Acceptance()], DateTime.UtcNow).Assess(Package());
        Assert.IsTrue(result.RangeUnknown);
        Assert.HasCount(1, result.Blocking);
    }

    [TestMethod]
    [DataRow("normal")]
    [DataRow("block")]
    [DataRow("unapproved")]
    [DataRow("stale")]
    [DataRow("failed-audit")]
    [DataRow("version-exclusion")]
    public async Task AdmissionRetainsOtherPolicyAndFreshnessRequirements(string condition)
    {
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("risk-acceptance-" + Guid.NewGuid()).Options);
        var now = DateTime.UtcNow;
        db.Vulnerabilities.Add(Advisory());
        db.Rules.Add(Acceptance());
        var approval = new PackageRule { Id = 20, Status = RuleStatus.Approved, Ecosystem = "npm", PackagePattern = "picomatch",
            Version = "*", Source = Source, RequestedAtUtc = now.AddDays(-1) };
        if (condition != "unapproved") db.Rules.Add(approval);
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastSuccessfulAttemptAtUtc = now.AddMinutes(-2),
            LastSuccessAtUtc = condition == "stale" ? now.AddHours(-13) : now.AddMinutes(-1),
            LastAttemptAtUtc = condition == "failed-audit" ? now : now.AddMinutes(-2),
            LastError = condition == "failed-audit" ? "Unavailable" : null
        });
        if (condition == "block") db.Rules.Add(new PackageRule { Kind = RuleKind.Block,
            Status = RuleStatus.Approved, Ecosystem = "npm", PackagePattern = "picomatch", Version = "*" });
        if (condition == "version-exclusion") db.Rules.Add(new PackageRule { Kind = RuleKind.VulnerabilityExclusion,
            ParentRuleId = 20, VulnerabilityId = 1 });
        await db.SaveChangesAsync();
        var result = (await new TrustService(db).AssessAsync([Package()])).Single();
        Assert.AreEqual(condition is "normal" or "failed-audit", result.Trusted);
        if (condition == "normal") StringAssert.Contains(result.Reason, "risk accepted");
        var state = await VulnerabilityPolicy.LoadAsync(db, now, [Package()]);
        Assert.HasCount(1, state.Assess(Package()).Findings);
        Assert.IsFalse(await db.Vulnerabilities.AnyAsync(v => v.Withdrawn));
    }
}
