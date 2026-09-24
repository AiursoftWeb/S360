using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.Sqlite;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests;

[TestClass]
public class SupplyChainPolicyTests
{
    private static Dependency Package(string name = "Microsoft.Extensions.Logging", string version = "10.0.8") => new()
    {
        Ecosystem = "nuget", Name = name, Version = version,
        Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64)
    };

    private static TrustRule Rule(string pattern = "Microsoft.*", string version = "10.0.*") => new()
    {
        Id = 1, Ecosystem = "nuget", PackagePattern = pattern, Version = version,
        Source = "https://api.nuget.org/v3/index.json", Status = TrustRuleStatus.Approved,
        ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
    };

    [TestMethod]
    public void SupplierMayHaveIndependentPrefixes()
    {
        var rules = new[] { Rule(), Rule("System.*") };
        Assert.IsTrue(TrustService.Evaluate(Package(), rules, [], DateTime.UtcNow).Trusted);
        Assert.IsTrue(TrustService.Evaluate(Package("System.Text.Json"), rules, [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package("System"), rules, [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public void UnrelatedTransitivePackageDoesNotInheritRootApproval()
    {
        Assert.IsFalse(TrustService.Evaluate(Package("Unknown.Transitive"), [Rule()], [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public void AbsoluteBlockOverridesApproval()
    {
        var block = new BlockRule { Active = true, Ecosystem = "nuget", PackagePattern = "Microsoft.*", Version = "*", Reason = "Incident" };
        var result = TrustService.Evaluate(Package(), [Rule()], [block], DateTime.UtcNow);
        Assert.IsFalse(result.Trusted);
        StringAssert.Contains(result.Reason, "Incident");
        StringAssert.Contains(result.Reason, "Microsoft.* @ *");
        StringAssert.Contains(result.Reason, "Microsoft.Extensions.Logging@10.0.8");
    }

    [TestMethod]
    public void PinnedHashCannotBeBypassedByWildcard()
    {
        var pinned = Rule("Microsoft.Extensions.Logging", "10.0.8");
        pinned.Sha256 = new string('b', 64);
        Assert.IsFalse(TrustService.Evaluate(Package(), [pinned, Rule()], [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public void ExpiredRuleAndNewPrereleaseAreDenied()
    {
        var expired = Rule();
        expired.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
        Assert.IsFalse(TrustService.Evaluate(Package(), [expired], [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package(version: "10.0.9-preview.1"), [Rule()], [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public void NpmNameMatchingIsCaseSensitive()
    {
        Assert.IsTrue(TrustPattern.Matches("@example/*", "@example/ui", "npm"));
        Assert.IsFalse(TrustPattern.Matches("@example/*", "@Example/ui", "npm"));
    }

    [TestMethod]
    public void ConcretePackageIdentityRejectsPatternsAndFieldSeparators()
    {
        Assert.IsTrue(TrustPattern.IsValidConcretePackage("nuget", "Microsoft.Extensions.Logging", "10.0.8"));
        Assert.IsTrue(TrustPattern.IsValidConcretePackage("npm", "@example/ui", "1.2.3"));
        Assert.IsFalse(TrustPattern.IsValidConcretePackage("nuget", "Microsoft.*", "10.0.8"));
        Assert.IsFalse(TrustPattern.IsValidConcretePackage("nuget", "Microsoft.Safe\n1.0.0", "10.0.8"));
        Assert.IsFalse(TrustPattern.IsValidConcretePackage("nuget", "Microsoft/Safe", "10.0.8"));
        Assert.IsFalse(TrustPattern.IsValidConcretePackage("npm", "@example/ui", "1.*"));
        Assert.IsFalse(TrustPattern.IsValidConcretePackage("npm", "@example/ui", "1.2.3\nother"));
    }

    [TestMethod]
    public void VersionPatternCoverageIsConservativeAboutPartialRangesAndPrereleases()
    {
        Assert.IsTrue(TrustPattern.VersionPatternCovers("10.*", "10.0.*", "nuget"));
        Assert.IsTrue(TrustPattern.VersionPatternCovers("10.0.*", "10.0.2", "nuget"));
        Assert.IsFalse(TrustPattern.VersionPatternCovers("10.0.*", "10.*", "nuget"));
        Assert.IsFalse(TrustPattern.VersionPatternCovers("10.*", "10.0.*", "nuget",
            innerIncludesPrerelease: true));
        Assert.IsTrue(TrustPattern.VersionPatternCovers("10.*", "10.0.*", "nuget",
            outerIncludesPrerelease: true, innerIncludesPrerelease: true));
        Assert.IsFalse(TrustPattern.VersionPatternCovers("10.*", "11.0.*", "nuget"));
    }

    [TestMethod]
    public async Task FirstApprovedWildcardHashIsPinnedForFutureChecks()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-hash-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        db.TrustRules.Add(Rule());
        await db.SaveChangesAsync();
        var service = new TrustService(db);
        var first = await service.CheckAsync([Package()]);
        Assert.IsFalse(first.Single().Trusted);
        StringAssert.Contains(first.Single().Reason, "verification and vulnerability audit are pending");
        Assert.AreEqual(1, await db.PackageArtifacts.CountAsync());
        var artifact = await db.PackageArtifacts.SingleAsync();
        Assert.IsNull(artifact.FirstTrustedAtUtc);
        artifact.SourceVerifiedAtUtc = DateTime.UtcNow;
        artifact.LastCheckedAtUtc = DateTime.UtcNow;
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = artifact.LastCheckedAtUtc.Value.AddSeconds(-1),
            LastSuccessAtUtc = artifact.LastCheckedAtUtc.Value.AddSeconds(1)
        });
        await db.SaveChangesAsync();
        var approved = await service.CheckAsync([Package()]);
        Assert.IsTrue(approved.Single().Trusted);
        var changed = Package();
        changed.Sha256 = new string('b', 64);
        var second = await service.CheckAsync([changed]);
        Assert.IsFalse(second.Single().Trusted);
        Assert.AreEqual(1, await db.PackageArtifacts.CountAsync());
    }

    [TestMethod]
    public async Task VulnerabilityAuditAloneCannotTrustAClientReportedArchiveHash()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-unverified-archive-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var dependency = Package();
        var checkedAt = DateTime.UtcNow;
        db.TrustRules.Add(Rule());
        db.PackageArtifacts.Add(new PackageArtifact
        {
            Ecosystem = dependency.Ecosystem, Name = dependency.Name, Version = dependency.Version,
            Source = dependency.Source, Sha256 = dependency.Sha256,
            LastCheckedAtUtc = checkedAt
        });
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = checkedAt.AddSeconds(-1),
            LastSuccessAtUtc = checkedAt.AddSeconds(1)
        });
        await db.SaveChangesAsync();

        var result = (await new TrustService(db).CheckAsync([dependency])).Single();

        Assert.IsFalse(result.Trusted);
        StringAssert.Contains(result.Reason, "has not been independently verified");
        Assert.IsNull((await db.PackageArtifacts.SingleAsync()).FirstTrustedAtUtc);
    }

    [TestMethod]
    public async Task SqliteCheckFindsOnlyRequestedArtifactWithNuGetCaseInsensitiveName()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite(connection).Options;
        await using var db = new SqliteContext(options);
        await db.Database.EnsureCreatedAsync();
        var now = DateTime.UtcNow;
        var rule = Rule();
        rule.Supplier = new Supplier { Name = "SQLite test supplier" };
        db.TrustRules.Add(rule);
        db.PackageArtifacts.AddRange(
            new PackageArtifact
            {
                Ecosystem = "nuget", Name = "MICROSOFT.EXTENSIONS.LOGGING", Version = "10.0.8",
                Source = Package().Source, Sha256 = Package().Sha256,
                SourceVerifiedAtUtc = now.AddMinutes(-1),
                FirstTrustedAtUtc = now.AddMinutes(-1), LastCheckedAtUtc = now
            },
            new PackageArtifact
            {
                Ecosystem = "nuget", Name = "Unrelated.Package", Version = "10.0.8",
                Source = Package().Source, Sha256 = new string('b', 64)
            });
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = now.AddSeconds(-1), LastSuccessAtUtc = now.AddSeconds(1)
        });
        await db.SaveChangesAsync();

        var dependency = Package("microsoft.extensions.logging");
        var decisions = await new TrustService(db).CheckAsync([dependency]);
        Assert.IsTrue(decisions.Single().Trusted, decisions.Single().Reason);
        Assert.AreEqual(2, await db.PackageArtifacts.CountAsync());
    }

    [TestMethod]
    public async Task PartialVulnerabilitySyncCannotMakeAReportedPackageTrusted()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-partial-audit-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var package = Package();
        var previousSuccess = DateTime.UtcNow.AddMinutes(-30);
        var partialCheck = DateTime.UtcNow;
        db.TrustRules.Add(Rule());
        db.PackageArtifacts.Add(new PackageArtifact
        {
            Ecosystem = package.Ecosystem, Name = package.Name, Version = package.Version,
            Source = package.Source, Sha256 = package.Sha256,
            SourceVerifiedAtUtc = previousSuccess,
            FirstTrustedAtUtc = previousSuccess, LastCheckedAtUtc = partialCheck
        });
        var audit = new VulnerabilitySyncState
        {
            LastAttemptAtUtc = previousSuccess.AddSeconds(-1), LastSuccessAtUtc = previousSuccess
        };
        db.VulnerabilitySyncStates.Add(audit);
        await db.SaveChangesAsync();

        var service = new TrustService(db);
        var beforeCompletion = (await service.AssessAsync([package])).Single();
        Assert.IsFalse(beforeCompletion.Trusted);
        StringAssert.Contains(beforeCompletion.Reason, "has not completed");

        audit.LastAttemptAtUtc = partialCheck.AddSeconds(-1);
        audit.LastSuccessAtUtc = partialCheck.AddSeconds(1);
        await db.SaveChangesAsync();
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
    }

    [TestMethod]
    public async Task FailedLatestVulnerabilitySyncCannotReuseFreshPreviousSuccess()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-failed-audit-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var package = Package();
        var lastCheck = DateTime.UtcNow.AddMinutes(-10);
        db.TrustRules.Add(Rule());
        db.PackageArtifacts.Add(new PackageArtifact
        {
            Ecosystem = package.Ecosystem, Name = package.Name, Version = package.Version,
            Source = package.Source, Sha256 = package.Sha256,
            SourceVerifiedAtUtc = lastCheck,
            FirstTrustedAtUtc = lastCheck, LastCheckedAtUtc = lastCheck
        });
        var audit = new VulnerabilitySyncState
        {
            LastAttemptAtUtc = lastCheck.AddSeconds(-1), LastSuccessAtUtc = lastCheck.AddSeconds(1)
        };
        db.VulnerabilitySyncStates.Add(audit);
        await db.SaveChangesAsync();

        var service = new TrustService(db);
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
        audit.LastAttemptAtUtc = DateTime.UtcNow;
        audit.LastError = "OSV temporarily unavailable";
        await db.SaveChangesAsync();

        var failed = (await service.AssessAsync([package])).Single();
        Assert.IsFalse(failed.Trusted);
        StringAssert.Contains(failed.Reason, "synchronization failed");

        audit.LastError = null;
        audit.LastSuccessAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        Assert.IsFalse((await service.AssessAsync([package])).Single().Trusted);
        var artifact = await db.PackageArtifacts.SingleAsync();
        artifact.LastCheckedAtUtc = audit.LastAttemptAtUtc.Value.AddTicks(1);
        await db.SaveChangesAsync();
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
    }

    [TestMethod]
    public async Task ReadOnlyAssessmentDoesNotPinUnreviewedBytes()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-assess-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        db.TrustRules.Add(Rule());
        await db.SaveChangesAsync();
        var result = (await new TrustService(db).AssessAsync([Package()])).Single();
        Assert.IsFalse(result.Trusted);
        StringAssert.Contains(result.Reason, "verification and vulnerability audit are pending");
        Assert.AreEqual(0, await db.PackageArtifacts.CountAsync());
    }

    [TestMethod]
    public async Task ExcludedAdvisoryBlocksOnlyItsAffectedVersions()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-exclusion-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var rule = Rule();
        db.TrustRules.Add(rule);
        var advisory = new Vulnerability
        {
            SourceId = "GHSA-test", Ecosystem = "nuget", PackageName = "Microsoft.Extensions.Logging",
            RawAffectedJson = """
                [{"package":{"ecosystem":"NuGet","name":"Microsoft.Extensions.Logging"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                """
        };
        db.Vulnerabilities.Add(advisory);
        await db.SaveChangesAsync();
        db.TrustRuleVulnerabilityExclusions.Add(new TrustRuleVulnerabilityExclusion
        {
            TrustRuleId = rule.Id, VulnerabilityId = advisory.Id, Reason = "Use fixed versions"
        });
        var vulnerable = Package(version: "10.0.2");
        var fixedPackage = Package(version: "10.0.8");
        db.PackageArtifacts.AddRange(
            new PackageArtifact { Ecosystem = "nuget", Name = vulnerable.Name, Version = vulnerable.Version,
                Source = vulnerable.Source, Sha256 = vulnerable.Sha256, LastCheckedAtUtc = DateTime.UtcNow,
                SourceVerifiedAtUtc = DateTime.UtcNow, FirstTrustedAtUtc = DateTime.UtcNow },
            new PackageArtifact { Ecosystem = "nuget", Name = fixedPackage.Name, Version = fixedPackage.Version,
                Source = fixedPackage.Source, Sha256 = fixedPackage.Sha256, LastCheckedAtUtc = DateTime.UtcNow,
                SourceVerifiedAtUtc = DateTime.UtcNow, FirstTrustedAtUtc = DateTime.UtcNow });
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = DateTime.UtcNow.AddSeconds(-1),
            LastSuccessAtUtc = DateTime.UtcNow.AddSeconds(1)
        });
        await db.SaveChangesAsync();
        var decisions = await new TrustService(db).CheckAsync([vulnerable, fixedPackage]);
        Assert.IsFalse(decisions[0].Trusted);
        Assert.IsTrue(decisions[1].Trusted);
    }

    [TestMethod]
    public void VersionExclusionCannotBeBypassedByOverlappingApproval()
    {
        var excludedRule = Rule();
        var alternateRule = Rule();
        alternateRule.Id = 2;
        var vulnerability = new Vulnerability
        {
            SourceId = "GHSA-overlap", Ecosystem = "nuget", PackageName = "Microsoft.Extensions.Logging",
            RawAffectedJson = """
                [{"package":{"ecosystem":"NuGet","name":"Microsoft.Extensions.Logging"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                """
        };
        var exclusions = new[]
        {
            new TrustRuleVulnerabilityExclusion { TrustRuleId = excludedRule.Id, Vulnerability = vulnerability }
        };
        var vulnerable = Package(version: "10.0.2");
        var firstOrder = TrustService.Evaluate(vulnerable, [excludedRule, alternateRule], [],
            DateTime.UtcNow, exclusions);
        var oppositeOrder = TrustService.Evaluate(vulnerable, [alternateRule, excludedRule], [],
            DateTime.UtcNow, exclusions);
        Assert.IsFalse(firstOrder.Trusted);
        Assert.IsFalse(oppositeOrder.Trusted);
        StringAssert.Contains(firstOrder.Reason, "GHSA-overlap");
        StringAssert.Contains(oppositeOrder.Reason, "GHSA-overlap");

        alternateRule.PackagePattern = vulnerable.Name;
        alternateRule.Version = vulnerable.Version;
        alternateRule.Sha256 = vulnerable.Sha256;
        var pinned = TrustService.Evaluate(vulnerable, [excludedRule, alternateRule], [],
            DateTime.UtcNow, exclusions);
        Assert.IsFalse(pinned.Trusted);
        StringAssert.Contains(pinned.Reason, "GHSA-overlap");

        excludedRule.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
        Assert.IsTrue(TrustService.Evaluate(vulnerable, [excludedRule, alternateRule], [],
            DateTime.UtcNow, exclusions).Trusted);

        excludedRule.ExpiresAtUtc = DateTime.UtcNow.AddDays(1);
        alternateRule.ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-1);
        var excluded = TrustService.Evaluate(vulnerable, [excludedRule, alternateRule], [],
            DateTime.UtcNow, exclusions);
        Assert.IsFalse(excluded.Trusted);
        StringAssert.Contains(excluded.Reason, "GHSA-overlap");
    }

    [TestMethod]
    public async Task UnapprovedObservationCannotPinTheTrustedHash()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-observation-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        db.TrustRules.Add(Rule());
        var observed = Package();
        db.PackageArtifacts.Add(new PackageArtifact
        {
            Ecosystem = observed.Ecosystem, Name = observed.Name, Version = observed.Version,
            Source = observed.Source, Sha256 = new string('b', 64)
        });
        await db.SaveChangesAsync();
        var decision = (await new TrustService(db).CheckAsync([observed])).Single();
        Assert.IsFalse(decision.Trusted);
        StringAssert.Contains(decision.Reason, "verification and vulnerability audit are pending");
        Assert.AreEqual(2, await db.PackageArtifacts.CountAsync());
        Assert.IsNull((await db.PackageArtifacts.SingleAsync(a => a.Sha256 == new string('b', 64))).FirstTrustedAtUtc);
        Assert.IsNull((await db.PackageArtifacts.SingleAsync(a => a.Sha256 == observed.Sha256)).FirstTrustedAtUtc);
    }

    [TestMethod]
    public async Task ConflictingTrustedHashesForOnePackageIdentityFailClosed()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-conflicting-trust-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        db.TrustRules.Add(Rule());
        var package = Package();
        var now = DateTime.UtcNow;
        db.PackageArtifacts.AddRange(
            new PackageArtifact
            {
                Ecosystem = package.Ecosystem, Name = package.Name, Version = package.Version,
                Source = package.Source, Sha256 = package.Sha256,
                SourceVerifiedAtUtc = now, FirstTrustedAtUtc = now, LastCheckedAtUtc = now
            },
            new PackageArtifact
            {
                Ecosystem = package.Ecosystem, Name = package.Name, Version = package.Version,
                Source = package.Source, Sha256 = new string('b', 64),
                SourceVerifiedAtUtc = now, FirstTrustedAtUtc = now, LastCheckedAtUtc = now
            });
        await db.SaveChangesAsync();

        var service = new TrustService(db);
        foreach (var hash in new[] { package.Sha256, new string('b', 64) })
        {
            var attempted = Package();
            attempted.Sha256 = hash;
            var decision = (await service.CheckAsync([attempted])).Single();
            Assert.IsFalse(decision.Trusted);
            StringAssert.Contains(decision.Reason, "Conflicting previously verified package hashes");
        }
    }
}
