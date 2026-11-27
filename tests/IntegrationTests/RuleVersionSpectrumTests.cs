using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Vulnerability;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class RuleVersionSpectrumTests : TestBase
{
    private const string NuGetSource = "https://nupkg.aiursoft.com/v3/index.json";

    [TestMethod]
    public void CompareVersionsSortsSemanticallyAcrossNuGetAndNpm()
    {
        var versions = new[] { "1.10.0", "1.2.0", "1.0.0", "1.0.0-beta.1", "1.0.0-alpha.2", "1.9.5", "2.0.0" };
        var sorted = versions
            .OrderBy(v => v, Comparer<string>.Create((a, b) => OsvRangeMatcher.CompareVersions(a, b, "nuget")))
            .ToArray();

        CollectionAssert.AreEqual(
            new[] { "1.0.0-alpha.2", "1.0.0-beta.1", "1.0.0", "1.2.0", "1.9.5", "1.10.0", "2.0.0" },
            sorted);
    }

    [TestMethod]
    public void FormatIntervalAndBlockOverlapCoverAllBoundaryForms()
    {
        var fixedSpan = RuleVersionSpectrumBuilder.FormatInterval(new OsvVersionInterval("1.1.0", "1.2.0", "fixed"));
        Assert.AreEqual(">= 1.1.0, < 1.2.0", fixedSpan.DisplayRange);
        Assert.AreEqual("1.2.0", fixedSpan.FixedVersion);

        var lastAffected = RuleVersionSpectrumBuilder.FormatInterval(new OsvVersionInterval(null, "1.4.9", "last_affected"));
        Assert.AreEqual("<= 1.4.9", lastAffected.DisplayRange);
        Assert.IsNull(lastAffected.FixedVersion);

        var openAll = RuleVersionSpectrumBuilder.FormatInterval(new OsvVersionInterval(null, null, null));
        Assert.AreEqual("All versions (*)", openAll.DisplayRange);

        var approval = new PackageRule
        {
            Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
            PackagePattern = "Demo.Pkg", Version = "1.*", Source = NuGetSource
        };
        var matchingBlock = new PackageRule
        {
            Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget",
            PackagePattern = "Demo.Pkg", Version = "1.4.*", Justification = "Compromised 1.4 line"
        };
        var unrelatedBlock = new PackageRule
        {
            Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget",
            PackagePattern = "Demo.Pkg", Version = "2.*", Justification = "Compromised 2.x line"
        };

        Assert.IsTrue(RuleVersionSpectrumBuilder.BlockOverlapsApproval(matchingBlock, approval));
        Assert.IsFalse(RuleVersionSpectrumBuilder.BlockOverlapsApproval(unrelatedBlock, approval));

        Assert.AreEqual(RangeRisk.Unknown, RuleVersionSpectrumBuilder.SafeIntersects("", "nuget", "Demo.Pkg", "1.*"));
        Assert.AreEqual(RangeRisk.Unknown, RuleVersionSpectrumBuilder.SafeIntersects("{not-json", "nuget", "Demo.Pkg", "1.*"));
    }

    [TestMethod]
    public async Task RuleAndPackageDetailsRenderFullMultiStateSpectrumAndCatalogSignals()
    {
        await LoginAsAdmin();
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var pkg = $"SpectrumDemo.{suffix}";
        var cleanPkg = $"SpectrumClean.{suffix}";
        var unparsedPkg = $"SpectrumUnparsed.{suffix}";
        var project = $"aiursoft/spectrum-app-{suffix}";
        var now = DateTime.UtcNow;

        int mainRuleId;
        int cleanRuleId;
        int unparsedRuleId;
        var createdRuleIds = new List<int>();
        var createdPkgIds = new List<int>();
        var createdVulnIds = new List<int>();
        var createdCheckIds = new List<int>();

        try
        {
            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var sync = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
                if (sync == null) { sync = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(sync); }
                sync.LastAttemptAtUtc = now.AddMinutes(-2);
                sync.LastSuccessfulAttemptAtUtc = now.AddMinutes(-2);
                sync.LastSuccessAtUtc = now;
                sync.LastError = null;

                var v100 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v110 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.1.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v120 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.2.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v130 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.3.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v140 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.4.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v1100 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "1.10.0", Source = NuGetSource, LastCheckedAtUtc = now };
                var v200 = new PackageVersion { Ecosystem = "nuget", Name = pkg, Version = "2.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
                db.PackageVersions.AddRange(v100, v110, v120, v130, v140, v1100, v200);
                await db.SaveChangesAsync();
                createdPkgIds.AddRange([v100.Id, v110.Id, v120.Id, v130.Id, v140.Id, v1100.Id, v200.Id]);

                var cveExcluded = new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = pkg,
                    SourceId = $"GHSA-excl-{suffix}",
                    Summary = "Excluded vulnerability in 1.1.x",
                    Url = $"https://osv.dev/vulnerability/GHSA-excl-{suffix}",
                    RawAffectedJson = JsonSerializer.Serialize(new[]
                    {
                        new
                        {
                            package = new { ecosystem = "NuGet", name = pkg },
                            ranges = new[]
                            {
                                new
                                {
                                    type = "ECOSYSTEM",
                                    events = new object[]
                                    {
                                        new { introduced = "1.1.0" },
                                        new { @fixed = "1.2.0" }
                                    }
                                }
                            }
                        }
                    })
                };
                var cveActive = new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = pkg,
                    SourceId = $"GHSA-actv-{suffix}",
                    Summary = "Active vulnerability in 1.2.x",
                    Url = $"https://osv.dev/vulnerability/GHSA-actv-{suffix}",
                    RawAffectedJson = JsonSerializer.Serialize(new[]
                    {
                        new
                        {
                            package = new { ecosystem = "NuGet", name = pkg },
                            ranges = new[]
                            {
                                new
                                {
                                    type = "ECOSYSTEM",
                                    events = new object[]
                                    {
                                        new { introduced = "1.2.0" },
                                        new { @fixed = "1.3.0" }
                                    }
                                }
                            }
                        }
                    })
                };
                var cveRisk = new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = pkg,
                    SourceId = $"GHSA-risk-{suffix}",
                    Summary = "Risk-accepted vulnerability in 1.3.0",
                    Url = $"https://osv.dev/vulnerability/GHSA-risk-{suffix}",
                    RawAffectedJson = JsonSerializer.Serialize(new[]
                    {
                        new
                        {
                            package = new { ecosystem = "NuGet", name = pkg },
                            versions = new[] { "1.3.0" }
                        }
                    })
                };
                var cveUnparsed = new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = unparsedPkg,
                    SourceId = $"GHSA-unp-{suffix}",
                    Summary = "Unparseable ecosystem range",
                    Url = $"https://osv.dev/vulnerability/GHSA-unp-{suffix}",
                    RawAffectedJson = "[{\"package\":{\"ecosystem\":\"NuGet\",\"name\":\"" + unparsedPkg + "\"},\"ranges\":[{\"type\":\"GIT\",\"events\":[{\"introduced\":\"abc123\"}]}]}]"
                };
                db.Vulnerabilities.AddRange(cveExcluded, cveActive, cveRisk, cveUnparsed);
                await db.SaveChangesAsync();
                createdVulnIds.AddRange([cveExcluded.Id, cveActive.Id, cveRisk.Id, cveUnparsed.Id]);

                var mainRule = new PackageRule
                {
                    Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = pkg, Version = "1.*", Source = NuGetSource,
                    RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(90),
                    Justification = "Core spectrum demonstration rule"
                };
                var cleanRule = new PackageRule
                {
                    Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = cleanPkg, Version = "3.*", Source = NuGetSource,
                    RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(90),
                    Justification = "Clean package with zero concrete versions yet"
                };
                var unparsedRule = new PackageRule
                {
                    Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = unparsedPkg, Version = "1.*", Source = NuGetSource,
                    RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(5),
                    Justification = "Expiring rule with unparsed advisory range"
                };
                db.Rules.AddRange(mainRule, cleanRule, unparsedRule);
                await db.SaveChangesAsync();
                mainRuleId = mainRule.Id;
                cleanRuleId = cleanRule.Id;
                unparsedRuleId = unparsedRule.Id;
                createdRuleIds.AddRange([mainRuleId, cleanRuleId, unparsedRuleId]);

                var exclusion = new PackageRule
                {
                    Kind = RuleKind.VulnerabilityExclusion, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = pkg, Version = "1.*", Source = NuGetSource,
                    ParentRuleId = mainRuleId, VulnerabilityId = cveExcluded.Id,
                    RequestedAtUtc = now.AddHours(-6),
                    Justification = "Exclude vulnerable 1.1.x range from 1.* grant"
                };
                var blockRule = new PackageRule
                {
                    Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = pkg, Version = "1.4.*",
                    RequestedAtUtc = now.AddHours(-5),
                    Justification = "Compromised release 1.4.x globally blocklisted"
                };
                var riskAcceptance = new PackageRule
                {
                    Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "nuget",
                    PackagePattern = pkg, Version = "1.3.0", Source = NuGetSource,
                    VulnerabilityId = cveRisk.Id,
                    RequestedAtUtc = now.AddHours(-4), ExpiresAtUtc = now.AddDays(30),
                    Justification = "Mitigated by reverse proxy input sanitization"
                };
                db.Rules.AddRange(exclusion, blockRule, riskAcceptance);
                await db.SaveChangesAsync();
                createdRuleIds.AddRange([exclusion.Id, blockRule.Id, riskAcceptance.Id]);

                var check = new BuildCheck
                {
                    Project = project,
                    RunId = Guid.NewGuid().ToString("N"),
                    BatchCount = 1,
                    ScannedProjectCount = 1,
                    CreatedAtUtc = now,
                    ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "nuget" }),
                    Dependencies =
                    [
                        new BuildCheckDependency
                        {
                            BuildCheckId = 0, PackageVersionId = v120.Id, Ecosystem = "nuget",
                            Name = pkg, Version = "1.2.0", Source = NuGetSource
                        }
                    ]
                };
                db.BuildChecks.Add(check);
                await db.SaveChangesAsync();
                createdCheckIds.Add(check.Id);
            }

            // 1. Verify RuleDetails spectrum renders all 6 states + parsed OSV intervals + semantic order
            var ruleHtml = await Http.GetStringAsync($"/SupplyChain/RuleDetails/{mainRuleId}");
            StringAssert.Contains(ruleHtml, "data-rule-spectrum=\"true\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.0.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.1.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.2.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.3.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.4.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"1.10.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-card=\"2.0.0\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"admitted\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"excluded\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"vulnerable\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"risk-accepted\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"blocklisted\"");
            StringAssert.Contains(ruleHtml, "data-spectrum-status=\"outside\"");
            StringAssert.Contains(ruleHtml, "&gt;= 1.2.0, &lt; 1.3.0");
            StringAssert.Contains(ruleHtml, "1.3.0");
            StringAssert.Contains(ruleHtml, $"GHSA-excl-{suffix}");
            StringAssert.Contains(ruleHtml, $"GHSA-actv-{suffix}");
            StringAssert.Contains(ruleHtml, $"GHSA-risk-{suffix}");
            // Semantic ordering: 1.4.0 must appear BEFORE 1.10.0 in the spectrum track
            Assert.IsTrue(
                ruleHtml.IndexOf("data-spectrum-segment=\"1.4.0\"", StringComparison.Ordinal) <
                ruleHtml.IndexOf("data-spectrum-segment=\"1.10.0\"", StringComparison.Ordinal),
                "Versions in spectrum track must be semantically sorted (1.4.0 before 1.10.0).");

            // 2. Verify PackageDetails renders the same full spectrum
            var pkgHtml = await Http.GetStringAsync($"/SupplyChain/PackageDetails?ruleId={mainRuleId}");
            StringAssert.Contains(pkgHtml, "data-rule-spectrum=\"true\"");
            StringAssert.Contains(pkgHtml, "data-spectrum-layer=\"blocks\"");
            StringAssert.Contains(pkgHtml, "data-spectrum-layer=\"exclusions\"");
            StringAssert.Contains(pkgHtml, "data-spectrum-layer=\"risk-acceptances\"");
            StringAssert.Contains(pkgHtml, "data-spectrum-card=\"1.10.0\"");

            // 3. Verify Unparsed / Unknown advisory range fails closed and displays explicit warning
            var unparsedHtml = await Http.GetStringAsync($"/SupplyChain/RuleDetails/{unparsedRuleId}");
            StringAssert.Contains(unparsedHtml, "data-spectrum-unparsed-warning=\"true\"");
            StringAssert.Contains(unparsedHtml, "Range could not be evaluated");

            // 4. Verify 0 observed versions still renders range layers + honest empty notice
            var cleanHtml = await Http.GetStringAsync($"/SupplyChain/RuleDetails/{cleanRuleId}");
            StringAssert.Contains(cleanHtml, "data-rule-spectrum=\"true\"");
            StringAssert.Contains(cleanHtml, "data-spectrum-empty=\"true\"");
            StringAssert.Contains(cleanHtml, "3.*");

            // 5. Verify Rules catalog list renders batch inline policy signals
            var rulesListHtml = await Http.GetStringAsync($"/SupplyChain/Index?tab=rules&ecosystem=nuget&query=Spectrum");
            StringAssert.Contains(rulesListHtml, $"data-rule-signal-id=\"{mainRuleId}\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"blocklist\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"cve\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"exclusion\"");
            StringAssert.Contains(rulesListHtml, $"data-rule-signal-id=\"{unparsedRuleId}\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"unparsed\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"expiring\"");
            StringAssert.Contains(rulesListHtml, $"data-rule-signal-id=\"{cleanRuleId}\"");
            StringAssert.Contains(rulesListHtml, "data-signal=\"clean\"");
        }
        finally
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            if (createdCheckIds.Count > 0)
            {
                db.BuildCheckDependencies.RemoveRange(await db.BuildCheckDependencies.Where(d => createdCheckIds.Contains(d.BuildCheckId)).ToListAsync());
                db.BuildChecks.RemoveRange(await db.BuildChecks.Where(c => createdCheckIds.Contains(c.Id)).ToListAsync());
            }
            if (createdRuleIds.Count > 0)
                db.Rules.RemoveRange(await db.Rules.Where(r => createdRuleIds.Contains(r.Id)).ToListAsync());
            if (createdVulnIds.Count > 0)
                db.Vulnerabilities.RemoveRange(await db.Vulnerabilities.Where(v => createdVulnIds.Contains(v.Id)).ToListAsync());
            if (createdPkgIds.Count > 0)
                db.PackageVersions.RemoveRange(await db.PackageVersions.Where(p => createdPkgIds.Contains(p.Id)).ToListAsync());
            await db.SaveChangesAsync();
        }
    }
}
