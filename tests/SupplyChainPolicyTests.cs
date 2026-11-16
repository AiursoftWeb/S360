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
    [TestMethod]
    [DataRow("LOW")]
    [DataRow("MODERATE")]
    [DataRow("HIGH")]
    [DataRow("CRITICAL")]
    [DataRow("")]
    public async Task WildcardApprovalCannotBypassAnyActiveVulnerability(string severity)
    {
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-severity-" + Guid.NewGuid()).Options);
        db.Rules.Add(Rule());
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastSuccessAtUtc = DateTime.UtcNow,
            LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1)
        });
        db.Vulnerabilities.Add(new Vulnerability
        {
            SourceId = "GHSA-severity-test", Ecosystem = "nuget",
            PackageName = "Microsoft.Extensions.Logging", Severity = severity,
            RawAffectedJson = """
                [{"package":{"ecosystem":"NuGet","name":"Microsoft.Extensions.Logging"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.0"},{"fixed":"10.0.8"}]}]}]
                """
        });
        await db.SaveChangesAsync();
        var decisions = await new TrustService(db).AssessAsync([Package(version: "10.0.7"), Package()]);
        Assert.IsFalse(decisions[0].Trusted);
        StringAssert.Contains(decisions[0].Reason, "GHSA-severity-test");
        Assert.IsTrue(decisions[1].Trusted);
    }

    private static Dependency Package(string name = "Microsoft.Extensions.Logging", string version = "10.0.8") => new()
    {
        Ecosystem = "nuget",
        Name = name,
        Version = version,
        Source = "https://api.nuget.org/v3/index.json"
    };

    private static PackageRule Rule(string pattern = "Microsoft.Extensions.Logging", string version = "10.0.*", int id = 1) => new()
    {
        ApplicationId = null,
        RequestedAtUtc = DateTime.UtcNow.AddHours(-2),
        Id = id,
        Ecosystem = "nuget",
        PackagePattern = pattern,
        Version = version,
        Source = "https://api.nuget.org/v3/index.json",
        Status = RuleStatus.Approved,
        ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
    };

    [TestMethod]
    public void ApprovalsForDifferentPackagesRemainIndependent()
    {
        var rules = new[] { Rule(), Rule("System.Text.Json") };
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
        var block = new PackageRule { Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = "Microsoft.*", Version = "*", Justification = "Incident" };
        var result = TrustService.Evaluate(Package(), [Rule()], [block], DateTime.UtcNow);
        Assert.IsFalse(result.Trusted);
        StringAssert.Contains(result.Reason, "Incident");
        StringAssert.Contains(result.Reason, "Microsoft.* @ *");
        StringAssert.Contains(result.Reason, "Microsoft.Extensions.Logging@10.0.8");
    }

    [TestMethod]
    public void HistoricalFileHashIsNotAPackagePolicyCondition()
    {
        var pinned = Rule("Microsoft.Extensions.Logging", "10.0.8");

        Assert.IsTrue(TrustService.Evaluate(Package(), [pinned, Rule()], [], DateTime.UtcNow).Trusted);
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
    public async Task SqliteCheckFindsOnlyRequestedArtifactWithNuGetCaseInsensitiveName()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<SqliteContext>().UseSqlite(connection).Options;
        await using var db = new SqliteContext(options);
        await db.Database.EnsureCreatedAsync();
        var now = DateTime.UtcNow;
        var rule = Rule();
        db.Rules.Add(rule);
        db.PackageVersions.AddRange(
            new PackageVersion
            {
                Ecosystem = "nuget",
                Name = "MICROSOFT.EXTENSIONS.LOGGING",
                Version = "10.0.8",
                Source = Package().Source,
                LastCheckedAtUtc = now
            },
            new PackageVersion
            {
                Ecosystem = "nuget",
                Name = "Unrelated.Package",
                Version = "10.0.8",
                Source = Package().Source
            });
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = now.AddSeconds(-1),
            LastSuccessfulAttemptAtUtc = now.AddSeconds(-1),
            LastSuccessAtUtc = now
        });
        await db.SaveChangesAsync();

        var dependency = Package("microsoft.extensions.logging");
        var decisions = await new TrustService(db).CheckAsync([dependency]);
        Assert.IsTrue(decisions.Single().Trusted, decisions.Single().Reason);
        Assert.AreEqual(2, await db.PackageVersions.CountAsync());
    }

    [TestMethod]
    public async Task InventoryCheckTimestampsDoNotChangePublishedPolicyVerdict()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-partial-audit-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var package = Package();
        var previousSuccess = DateTime.UtcNow.AddMinutes(-30);
        var partialCheck = DateTime.UtcNow;
        db.Rules.Add(Rule());
        db.PackageVersions.Add(new PackageVersion
        {
            Ecosystem = package.Ecosystem,
            Name = package.Name,
            Version = package.Version,
            Source = package.Source,
            LastCheckedAtUtc = partialCheck
        });
        var audit = new VulnerabilitySyncState
        {
            LastAttemptAtUtc = previousSuccess.AddSeconds(-1),
            LastSuccessfulAttemptAtUtc = previousSuccess.AddSeconds(-1),
            LastSuccessAtUtc = previousSuccess
        };
        db.VulnerabilitySyncStates.Add(audit);
        await db.SaveChangesAsync();

        var service = new TrustService(db);
        var beforeCompletion = (await service.AssessAsync([package])).Single();
        Assert.IsTrue(beforeCompletion.Trusted);

        audit.LastAttemptAtUtc = partialCheck.AddSeconds(-1);
        audit.LastSuccessfulAttemptAtUtc = partialCheck.AddSeconds(-1);
        audit.LastSuccessAtUtc = partialCheck;
        await db.SaveChangesAsync();
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
    }

    [TestMethod]
    public async Task RefreshAttemptsCannotInvalidateOrExtendPublishedResults()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-failed-audit-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var package = Package();
        var lastCheck = DateTime.UtcNow.AddMinutes(-10);
        db.Rules.Add(Rule());
        db.PackageVersions.Add(new PackageVersion
        {
            Ecosystem = package.Ecosystem,
            Name = package.Name,
            Version = package.Version,
            Source = package.Source,
            LastCheckedAtUtc = lastCheck
        });
        var audit = new VulnerabilitySyncState
        {
            LastAttemptAtUtc = lastCheck.AddSeconds(-1),
            LastSuccessfulAttemptAtUtc = lastCheck.AddSeconds(-1),
            LastSuccessAtUtc = lastCheck.AddSeconds(1)
        };
        db.VulnerabilitySyncStates.Add(audit);
        await db.SaveChangesAsync();

        var service = new TrustService(db);
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
        audit.LastAttemptAtUtc = DateTime.UtcNow;
        audit.LastError = "OSV temporarily unavailable";
        await db.SaveChangesAsync();

        var failed = (await service.AssessAsync([package])).Single();
        Assert.IsTrue(failed.Trusted);
        Assert.AreEqual(lastCheck.AddSeconds(1), audit.LastSuccessAtUtc);

        audit.LastError = null;
        audit.LastSuccessfulAttemptAtUtc = audit.LastAttemptAtUtc;
        audit.LastSuccessAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        Assert.IsTrue((await service.AssessAsync([package])).Single().Trusted);
        var artifact = await db.PackageVersions.SingleAsync();
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
        db.Rules.Add(Rule());
        await db.SaveChangesAsync();
        var result = (await new TrustService(db).AssessAsync([Package()])).Single();
        Assert.IsFalse(result.Trusted);
        StringAssert.Contains(result.Reason, "vulnerability data is unavailable");
        Assert.AreEqual(0, await db.PackageVersions.CountAsync());
    }

    [TestMethod]
    [DataRow("10.0.2")]
    [DataRow("10.0.0-preview.1")]
    public async Task ExcludedAdvisoryBlocksOnlyItsAffectedVersions(string introduced)
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-exclusion-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var rule = Rule();
        db.Rules.Add(rule);
        var advisory = new Vulnerability
        {
            SourceId = "GHSA-test",
            Ecosystem = "nuget",
            PackageName = "microsoft.extensions.logging",
            RawAffectedJson = $$"""
                [{"package":{"ecosystem":"NuGet","name":"Microsoft.Extensions.Logging"},"ranges":[{"type":"SEMVER","events":[{"introduced":"{{introduced}}"},{"fixed":"10.0.8"}]}]}]
                """
        };
        db.Vulnerabilities.Add(advisory);
        await db.SaveChangesAsync();
        db.Rules.Add(new PackageRule
        {
            Kind = RuleKind.VulnerabilityExclusion,
            ParentRuleId = rule.Id,
            VulnerabilityId = advisory.Id,
            Justification = "Use fixed versions"
        });
        var vulnerable = Package(version: "10.0.2");
        var fixedPackage = Package(version: "10.0.8");
        var siblingPackage = Package(name: "Microsoft.Extensions.Configuration", version: "10.0.2");
        db.Rules.Add(Rule("Microsoft.Extensions.Configuration", id: 3));
        db.PackageVersions.AddRange(
            new PackageVersion
            {
                Ecosystem = "nuget",
                Name = vulnerable.Name,
                Version = vulnerable.Version,
                Source = vulnerable.Source,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new PackageVersion
            {
                Ecosystem = "nuget",
                Name = fixedPackage.Name,
                Version = fixedPackage.Version,
                Source = fixedPackage.Source,
                LastCheckedAtUtc = DateTime.UtcNow
            },
            new PackageVersion
            {
                Ecosystem = "nuget",
                Name = siblingPackage.Name,
                Version = siblingPackage.Version,
                Source = siblingPackage.Source,
                LastCheckedAtUtc = DateTime.UtcNow
            });
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = DateTime.UtcNow.AddSeconds(-1),
            LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddSeconds(-1),
            LastSuccessAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        var decisions = await new TrustService(db).CheckAsync([vulnerable, fixedPackage, siblingPackage]);
        Assert.IsFalse(decisions[0].Trusted);
        Assert.IsTrue(decisions[1].Trusted);
        Assert.IsTrue(decisions[2].Trusted);
    }

    [TestMethod]
    public void VersionExclusionCannotBeBypassedByOverlappingApproval()
    {
        var excludedRule = Rule();
        var alternateRule = Rule(id: 2);
        var vulnerability = new Vulnerability
        {
            SourceId = "GHSA-overlap",
            Ecosystem = "nuget",
            PackageName = "Microsoft.Extensions.Logging",
            RawAffectedJson = """
                [{"package":{"ecosystem":"NuGet","name":"Microsoft.Extensions.Logging"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                """
        };
        var exclusions = new[]
        {
            new PackageRule { Kind = RuleKind.VulnerabilityExclusion,  VulnerabilityId = 0, ParentRuleId = excludedRule.Id, Vulnerability = vulnerability }
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
    [DataRow(false)]
    [DataRow(true)]
    public async Task HistoricalArchiveRecordsAndHashesCannotChangePolicyVerdict(bool conflictingHistory)
    {
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var rule = Rule();
        db.Rules.Add(rule);
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2),
            LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2),
            LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-1)
        });
        if (conflictingHistory)
            for (var i = 0; i < 2; i++)
                db.PackageVersions.Add(new PackageVersion
                {
                    Ecosystem = "nuget",
                    Name = Package().Name,
                    Version = Package().Version,
                    Source = Package().Source
                });
        await db.SaveChangesAsync();
        var count = await db.PackageVersions.CountAsync();
        var dependency = Package();
        {
            var decision = (await new TrustService(db).AssessAsync([dependency])).Single();
            Assert.IsTrue(decision.Trusted, decision.Reason);
        }
        Assert.AreEqual(count, await db.PackageVersions.CountAsync());
        rule.Status = RuleStatus.Revoked;
        await db.SaveChangesAsync();
        Assert.IsFalse((await new TrustService(db).AssessAsync([dependency])).Single().Trusted);
    }

    [TestMethod]
    public void ANewNameCannotInheritLegacyPrefixApprovalOrBypassLegacyDenial()
    {
        var legacy = Rule("Microsoft.*");
        var exact = Rule();
        Assert.IsFalse(TrustService.Evaluate(Package(), [legacy], [], DateTime.UtcNow).Trusted);
        Assert.IsTrue(TrustService.Evaluate(Package(), [legacy, exact], [], DateTime.UtcNow).Trusted);
        legacy.Status = RuleStatus.Revoked;
        Assert.IsFalse(TrustService.Evaluate(Package(), [legacy, exact], [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package("Microsoft.NewFake"), [exact], [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public async Task OnePackageSharesMultipleVersionGrantsWithoutWideningTheRange()
    {
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var old = Rule(version: "9.*", id: 1);
        var current = Rule(pattern: "microsoft.extensions.logging", version: "10.*", id: 2);
        var otherSource = Rule(id: 3);
        otherSource.Source = "https://nuget.aiursoft.com/v3/index.json";
        db.Rules.AddRange(old, current, otherSource);
        await db.SaveChangesAsync();
        Assert.IsTrue(TrustService.Evaluate(Package(version: "9.1.0"), [old, current], [], DateTime.UtcNow).Trusted);
        Assert.IsTrue(TrustService.Evaluate(Package(version: "10.1.0"), [old, current], [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package(version: "8.1.0"), [old, current], [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package(version: "11.1.0"), [old, current], [], DateTime.UtcNow).Trusted);
    }

    [TestMethod]
    public async Task ReviewedLegacyMigrationPreservesHistoryRangesAndExclusions()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new SqliteContext(new DbContextOptionsBuilder<SqliteContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();

        var original = Rule("Microsoft.*", "10.*");
        db.RuleChanges.Add(new RuleChange
        {
            Rule = original,
            RuleId = original.Id,
            ReviewerId = "original-reviewer",
            Decision = RuleStatus.Approved,
            Reason = "Original scope"
        });
        db.Rules.Add(original);
        db.PackageVersions.Add(new PackageVersion
        {
            Ecosystem = "nuget",
            Name = "Microsoft.Extensions.Logging",
            Version = "10.0.8",
            Source = original.Source
        });
        var advisory = new Vulnerability
        {
            Ecosystem = "nuget",
            PackageName = "Microsoft.Extensions.Logging",
            SourceId = "GHSA-migration",
            RawAffectedJson = "[]"
        };
        db.Rules.Add(new PackageRule
        {
            Kind = RuleKind.VulnerabilityExclusion,
            ParentRule = original,
            ParentRuleId = original.Id,
            Vulnerability = advisory,
            VulnerabilityId = advisory.Id,
            Justification = "Original exclusion",
            RequestedByUserId = "original-reviewer"
        });
        await db.SaveChangesAsync();
        var migration = new LegacyRuleMigration(db);
        var plan = await migration.PreviewAsync();
        Assert.AreEqual(1, plan.Rows.Count);
        await migration.ApplyAsync(plan.Fingerprint, [plan.Rows.Single().Key], "migration-reviewer", "Reviewed concrete package list");
        db.ChangeTracker.Clear();
        var grants = await db.Rules.Where(r => r.Kind == RuleKind.Approval).Include(r => r.Reviews).OrderBy(r => r.Id).ToListAsync();
        Assert.AreEqual(2, grants.Count);
        var migrated = grants.Single(r => r.LegacySourceRuleId == original.Id);
        Assert.AreEqual("10.*", migrated.Version);
        Assert.AreEqual(original.ExpiresAtUtc, migrated.ExpiresAtUtc);
        Assert.AreEqual(original.RequestedAtUtc, migrated.RequestedAtUtc);
        Assert.AreEqual("original-reviewer", grants[0].Reviews.Single().ReviewerId);
        Assert.AreEqual("migration-reviewer", migrated.Reviews.Single().ReviewerId);
        Assert.AreEqual(2, await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).CountAsync());
        Assert.IsTrue(TrustService.Evaluate(Package(), grants, [], DateTime.UtcNow).Trusted);
        Assert.IsFalse(TrustService.Evaluate(Package("Microsoft.NewFake"), grants, [], DateTime.UtcNow).Trusted);
        var repeated = await migration.PreviewAsync();
        Assert.AreEqual(0, repeated.Rows.Count);
        await migration.ApplyAsync(repeated.Fingerprint, [], "migration-reviewer", "No duplicate grants");
        Assert.AreEqual(2, await db.Rules.Where(r => r.Kind == RuleKind.Approval).CountAsync());
    }

    [TestMethod]
    public async Task MigrationRejectsStaleOrInventedSelectionsAndLegacyDenials()
    {
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var original = Rule("Microsoft.*");
        db.Rules.Add(original);
        await db.SaveChangesAsync();
        var service = new LegacyRuleMigration(db);
        var plan = await service.PreviewAsync();
        await Assert.ThrowsExactlyAsync<ArgumentException>(() => service.ApplyAsync(plan.Fingerprint,
            ["1:Microsoft.Fake"], "reviewer", "No invented names"));
        original.Status = RuleStatus.Revoked;
        await db.SaveChangesAsync();
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => service.ApplyAsync(plan.Fingerprint,
            [], "reviewer", "No stale decisions"));
        plan = await service.PreviewAsync();
        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => service.ApplyAsync(plan.Fingerprint,
            [], "reviewer", "Do not drop legacy denial"));
        Assert.AreEqual(1, await db.Rules.Where(r => r.Kind == RuleKind.Approval).CountAsync());
    }

}
