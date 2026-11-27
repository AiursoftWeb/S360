using System.Text.RegularExpressions;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Microsoft.EntityFrameworkCore;
using static Microsoft.Playwright.Assertions;

namespace Aiursoft.S360.Tests.BrowserTests;

[TestClass]
public class RuleVersionSpectrumBrowserTests : BrowserTestBase
{
    private const string NuGetSource = "https://nupkg.aiursoft.com/v3/index.json";

    [TestMethod]
    public async Task RuleVersionSpectrumFiltersSelectionAndCatalogSignalsWorkInRealBrowser()
    {
        var pageErrors = new List<string>();
        Page.PageError += (_, message) => pageErrors.Add(message);
        await Page.SetViewportSizeAsync(1440, 900);

        await SignInAsAdminAsync();

        var suffix = Guid.NewGuid().ToString("N")[..6];
        var pkg = $"Newtonsoft.Spectrum.{suffix}";
        var unparsedPkg = $"Legacy.Unparsed.{suffix}";
        var project = $"aiursoft/billing-api-{suffix}";
        var now = DateTime.UtcNow;

        int mainRuleId;
        var createdRuleIds = new List<int>();
        var createdPkgIds = new List<int>();
        var createdVulnIds = new List<int>();
        var createdCheckIds = new List<int>();

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
                Ecosystem = "nuget", PackageName = pkg, SourceId = $"GHSA-ex01-{suffix}",
                Summary = "Denial of service in 1.1.x XML reader",
                Url = $"https://osv.dev/vulnerability/GHSA-ex01-{suffix}",
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
                                events = new object[] { new { introduced = "1.1.0" }, new { @fixed = "1.2.0" } }
                            }
                        }
                    }
                })
            };
            var cveActive = new Vulnerability
            {
                Ecosystem = "nuget", PackageName = pkg, SourceId = $"GHSA-cv02-{suffix}",
                Summary = "Prototype/deserialization bypass in 1.2.x",
                Url = $"https://osv.dev/vulnerability/GHSA-cv02-{suffix}",
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
                                events = new object[] { new { introduced = "1.2.0" }, new { @fixed = "1.3.0" } }
                            }
                        }
                    }
                })
            };
            var cveRisk = new Vulnerability
            {
                Ecosystem = "nuget", PackageName = pkg, SourceId = $"GHSA-rk03-{suffix}",
                Summary = "ReDoS in optional regex formatter",
                Url = $"https://osv.dev/vulnerability/GHSA-rk03-{suffix}",
                RawAffectedJson = JsonSerializer.Serialize(new[]
                {
                    new { package = new { ecosystem = "NuGet", name = pkg }, versions = new[] { "1.3.0" } }
                })
            };
            var cveUnparsed = new Vulnerability
            {
                Ecosystem = "nuget", PackageName = unparsedPkg, SourceId = $"GHSA-up04-{suffix}",
                Summary = "Upstream advisory published with GIT commit range only",
                Url = $"https://osv.dev/vulnerability/GHSA-up04-{suffix}",
                RawAffectedJson = "[{\"package\":{\"ecosystem\":\"NuGet\",\"name\":\"" + unparsedPkg + "\"},\"ranges\":[{\"type\":\"GIT\",\"events\":[{\"introduced\":\"deadbeef\"}]}]}]"
            };
            db.Vulnerabilities.AddRange(cveExcluded, cveActive, cveRisk, cveUnparsed);
            await db.SaveChangesAsync();
            createdVulnIds.AddRange([cveExcluded.Id, cveActive.Id, cveRisk.Id, cveUnparsed.Id]);

            var mainRule = new PackageRule
            {
                Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = pkg, Version = "1.*", Source = NuGetSource,
                RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(120),
                Justification = "Standard JSON serialization package for internal services"
            };
            var siblingRule = new PackageRule
            {
                Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = pkg, Version = "1.10.0", Source = NuGetSource,
                RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(60),
                Justification = "Pinned release validated for production"
            };
            var unparsedRule = new PackageRule
            {
                Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = unparsedPkg, Version = "1.*", Source = NuGetSource,
                RequestedAtUtc = now.AddDays(-1), ExpiresAtUtc = now.AddDays(7),
                Justification = "Legacy codec pending upstream range clarification"
            };
            db.Rules.AddRange(mainRule, siblingRule, unparsedRule);
            await db.SaveChangesAsync();
            mainRuleId = mainRule.Id;
            createdRuleIds.AddRange([mainRule.Id, siblingRule.Id, unparsedRule.Id]);

            var exclusion = new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = pkg, Version = "1.*", Source = NuGetSource,
                ParentRuleId = mainRuleId, VulnerabilityId = cveExcluded.Id,
                RequestedAtUtc = now.AddHours(-4),
                Justification = "Subtracted 1.1.x DoS range from 1.* wildcard grant"
            };
            var blockRule = new PackageRule
            {
                Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = pkg, Version = "1.4.*",
                RequestedAtUtc = now.AddHours(-3),
                Justification = "1.4.x pulled due to supply chain tamper report"
            };
            var riskAcceptance = new PackageRule
            {
                Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "nuget",
                PackagePattern = pkg, Version = "1.3.0", Source = NuGetSource,
                VulnerabilityId = cveRisk.Id,
                RequestedAtUtc = now.AddHours(-2), ExpiresAtUtc = now.AddDays(25),
                Justification = "Regex formatter disabled via application config"
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
                    },
                    new BuildCheckDependency
                    {
                        BuildCheckId = 0, PackageVersionId = v1100.Id, Ecosystem = "nuget",
                        Name = pkg, Version = "1.10.0", Source = NuGetSource
                    }
                ]
            };
            db.BuildChecks.Add(check);
            await db.SaveChangesAsync();
            createdCheckIds.Add(check.Id);
        }

        try
        {
            // 1. RuleDetails Light mode (1440px): verify spectrum track order, layers, interactive filters & segment click
            await NavigateAsync($"/SupplyChain/RuleDetails/{mainRuleId}");
            var spectrum = Page.Locator("[data-rule-spectrum='true']");
            await Expect(spectrum).ToBeVisibleAsync();

            var segmentVersions = await spectrum.Locator("[data-spectrum-segment]").EvaluateAllAsync<string[]>(
                "els => els.map(e => e.getAttribute('data-spectrum-segment'))");
            CollectionAssert.AreEqual(
                new[] { "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.10.0", "2.0.0" },
                segmentVersions);

            await Expect(spectrum.Locator("[data-spectrum-card]")).ToHaveCountAsync(7);
            await CaptureIfRequestedAsync("01-rule-spectrum-light.png");

            // Interactive filter: Active CVE -> only 1.2.0 visible, other segments dimmed
            await spectrum.Locator("[data-spectrum-filter='vulnerable']").ClickAsync();
            await Expect(spectrum.Locator("[data-spectrum-card]:visible")).ToHaveCountAsync(1);
            await Expect(spectrum.Locator("[data-spectrum-card]:visible")).ToContainTextAsync("1.2.0");
            await Expect(spectrum.Locator("[data-spectrum-segment='1.0.0']")).ToHaveClassAsync(new Regex("is-dimmed"));

            // Click dimmed segment 1.1.0 -> auto-resets filter to All, highlights 1.1.0, opens evidence details
            await spectrum.Locator("[data-spectrum-segment='1.1.0']").ClickAsync();
            await Expect(spectrum.Locator("[data-spectrum-card]:visible")).ToHaveCountAsync(7);
            var card110 = spectrum.Locator("[data-spectrum-card='1.1.0']");
            await Expect(card110).ToHaveClassAsync(new Regex("is-highlighted"));
            await Expect(card110.Locator("details.s360-spectrum-evidence")).ToHaveAttributeAsync("open", "");
            await CaptureIfRequestedAsync("02-rule-spectrum-selected-light.png");

            // 2. PackageDetails Light mode (1440px)
            await NavigateAsync($"/SupplyChain/PackageDetails?ruleId={mainRuleId}");
            await Expect(Page.Locator("[data-rule-spectrum='true']")).ToBeVisibleAsync();
            await Expect(Page.Locator("[data-spectrum-layer='blocks']")).ToBeVisibleAsync();
            await Expect(Page.Locator("[data-spectrum-layer='exclusions']")).ToBeVisibleAsync();
            await Expect(Page.Locator("[data-spectrum-layer='risk-acceptances']")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("03-package-spectrum-light.png");

            // 3. Rules catalog list with inline policy signals (Light mode)
            await NavigateAsync($"/SupplyChain/Index?tab=rules&ecosystem=nuget&query={suffix}");
            var rulesTable = Page.Locator(".s360-catalog-rules");
            await Expect(rulesTable).ToBeVisibleAsync();
            await Expect(rulesTable.Locator("[data-signal='blocklist']")).ToBeVisibleAsync();
            await Expect(rulesTable.Locator("[data-signal='cve']").First).ToBeVisibleAsync();
            await Expect(rulesTable.Locator("[data-signal='exclusion']")).ToBeVisibleAsync();
            await Expect(rulesTable.Locator("[data-signal='unparsed']")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("04-rules-list-signals-light.png");

            // 4. Dark mode screenshots (1440px desktop + 430px mobile)
            await Page.EvaluateAsync("() => fetch('/api/switch-theme', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ theme: 'dark' }), credentials: 'same-origin' })");
            await NavigateAsync($"/SupplyChain/RuleDetails/{mainRuleId}");
            await Expect(Page.Locator("html")).ToHaveAttributeAsync("data-bs-theme", "dark");
            await Expect(Page.Locator("[data-rule-spectrum='true']")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("05-rule-spectrum-dark.png");

            var desktopOverflow = await Page.EvaluateAsync<int>("() => document.documentElement.scrollWidth - window.innerWidth");
            Assert.IsTrue(desktopOverflow <= 1, $"Desktop RuleDetails overflowed horizontally by {desktopOverflow}px.");

            await Page.SetViewportSizeAsync(430, 900);
            await Expect(Page.Locator("[data-rule-spectrum='true']")).ToBeVisibleAsync();
            var mobileOverflow = await Page.EvaluateAsync<int>("() => document.documentElement.scrollWidth - window.innerWidth");
            Assert.IsTrue(mobileOverflow <= 1, $"Mobile 430px RuleDetails overflowed horizontally by {mobileOverflow}px.");
            await CaptureIfRequestedAsync("06-rule-spectrum-mobile-dark.png");

            Assert.AreEqual(0, pageErrors.Count, "Unexpected page errors: " + string.Join("; ", pageErrors));
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

    private async Task CaptureIfRequestedAsync(string filename)
    {
        var dir = Environment.GetEnvironmentVariable("S360_VISUAL_CAPTURE_DIR");
        if (string.IsNullOrWhiteSpace(dir)) return;
        Directory.CreateDirectory(dir);
        await Page.ScreenshotAsync(new() { Path = Path.Combine(dir, filename), FullPage = true });
    }

    private async Task SignInAsAdminAsync()
    {
        await NavigateAsync("/Account/Login");
        var form = Page.Locator("form").Filter(new() { Has = Page.Locator("#EmailOrUserName") });
        await form.Locator("#EmailOrUserName").FillAsync("admin@default.com");
        await form.Locator("#Password").FillAsync("Admin@123456!");
        await form.Locator("button[type=submit]").ClickAsync();
        await Expect(Page).Not.ToHaveURLAsync(new Regex("/Account/Login", RegexOptions.IgnoreCase));
    }

    private async Task NavigateAsync(string path)
    {
        var response = await Page.GotoAsync(path);
        Assert.IsNotNull(response);
        Assert.IsTrue(response.Ok, $"{path}: HTTP {response.Status}");
    }
}
