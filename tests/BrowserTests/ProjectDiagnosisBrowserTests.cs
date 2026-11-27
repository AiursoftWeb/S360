using System.Text.Json;
using System.Text.RegularExpressions;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Microsoft.EntityFrameworkCore;
using Microsoft.Playwright;
using static Microsoft.Playwright.Assertions;

namespace Aiursoft.S360.Tests.BrowserTests;

[TestClass]
public class ProjectDiagnosisBrowserTests : BrowserTestBase
{
    private const string NuGetSource = "https://nupkg.aiursoft.com/v3/index.json";
    private const string NpmSource = "https://npm.aiursoft.com";

    [TestMethod]
    public async Task ProjectDiagnosisFiltersLazyGraphAndPrefillWorkInRealBrowser()
    {
        var pageErrors = new List<string>();
        Page.PageError += (_, message) => pageErrors.Add(message);
        await Page.SetViewportSizeAsync(1440, 900);

        await SignInAsAdminAsync();

        var suffix = Guid.NewGuid().ToString("N")[..6];
        var badProject = $"aiursoft/shop-portal-{suffix}";
        var goodProject = $"aiursoft/docs-site-{suffix}";
        var now = DateTime.UtcNow;

        var createdCheckIds = new List<int>();
        var createdPackageIds = new List<int>();
        var createdRuleIds = new List<int>();
        var createdVulnIds = new List<int>();

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var sync = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (sync == null) { sync = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(sync); }
            sync.LastAttemptAtUtc = now.AddMinutes(-3);
            sync.LastSuccessfulAttemptAtUtc = now.AddMinutes(-3);
            sync.LastSuccessAtUtc = now;
            sync.LastError = null;

            var blockedPkg = new PackageVersion { Ecosystem = "nuget", Name = $"LegacyCrypto.{suffix}", Version = "1.0.2", Source = NuGetSource, LastCheckedAtUtc = now };
            var unauthPkg = new PackageVersion { Ecosystem = "nuget", Name = $"CsvExporter.{suffix}", Version = "1.4.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var riskPkg = new PackageVersion { Ecosystem = "nuget", Name = $"XmlParser.{suffix}", Version = "2.1.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var cleanPkg = new PackageVersion { Ecosystem = "nuget", Name = $"Aiursoft.WebTools.{suffix}", Version = "10.0.1", Source = NuGetSource, LastCheckedAtUtc = now };
            var directNpm = new PackageVersion { Ecosystem = "npm", Name = $"ui-kit-{suffix}", Version = "3.1.0", Source = NpmSource, LastCheckedAtUtc = now };
            var vulnNpm = new PackageVersion { Ecosystem = "npm", Name = $"minimatch-demo-{suffix}", Version = "9.0.3", Source = NpmSource, LastCheckedAtUtc = now };
            db.PackageVersions.AddRange(blockedPkg, unauthPkg, riskPkg, cleanPkg, directNpm, vulnNpm);
            await db.SaveChangesAsync();
            createdPackageIds.AddRange([blockedPkg.Id, unauthPkg.Id, riskPkg.Id, cleanPkg.Id, directNpm.Id, vulnNpm.Id]);

            var cveActive = new Vulnerability
            {
                SourceId = $"GHSA-m2b1-{suffix}",
                Ecosystem = "npm",
                PackageName = vulnNpm.Name,
                Aliases = "[\"CVE-2026-55001\"]",
                RawAffectedJson = "[]"
            };
            var cveRisk = new Vulnerability
            {
                SourceId = $"GHSA-m2b2-{suffix}",
                Ecosystem = "nuget",
                PackageName = riskPkg.Name,
                Aliases = "[\"CVE-2026-55002\"]",
                RawAffectedJson = "[]"
            };
            db.Vulnerabilities.AddRange(cveActive, cveRisk);
            await db.SaveChangesAsync();
            createdVulnIds.AddRange([cveActive.Id, cveRisk.Id]);

            db.VulnerabilityMatches.AddRange(
                new VulnerabilityMatch { PackageVersionId = vulnNpm.Id, VulnerabilityId = cveActive.Id },
                new VulnerabilityMatch { PackageVersionId = riskPkg.Id, VulnerabilityId = cveRisk.Id }
            );

            var blockRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = blockedPkg.Name, Version = "1.*", Justification = "Broken signature verification in 1.x" };
            var otherUnauthRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = unauthPkg.Name, Version = "2.*", ExpiresAtUtc = now.AddDays(90), Justification = "2.x approved for exports" };
            var riskApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "2.*", ExpiresAtUtc = now.AddDays(90), Justification = "Internal XML ingestion" };
            var riskAcceptance = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "2.1.0", VulnerabilityId = cveRisk.Id, ExpiresAtUtc = now.AddDays(21), Justification = "External DTD disabled in host config" };
            var cleanApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = cleanPkg.Name, Version = "10.*", ExpiresAtUtc = now.AddDays(180), Justification = "Core Aiursoft web framework" };
            var npmDirectRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "npm", Source = NpmSource, PackagePattern = directNpm.Name, Version = "3.*", ExpiresAtUtc = now.AddDays(90), Justification = "Design system" };
            var npmVulnRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "npm", Source = NpmSource, PackagePattern = vulnNpm.Name, Version = "9.*", ExpiresAtUtc = now.AddDays(90), Justification = "Glob helper" };
            db.Rules.AddRange(blockRule, otherUnauthRule, riskApproval, riskAcceptance, cleanApproval, npmDirectRule, npmVulnRule);
            await db.SaveChangesAsync();
            createdRuleIds.AddRange([blockRule.Id, otherUnauthRule.Id, riskApproval.Id, riskAcceptance.Id, cleanApproval.Id, npmDirectRule.Id, npmVulnRule.Id]);

            var directNpmDep = new Dependency { Ecosystem = "npm", Name = directNpm.Name, Version = directNpm.Version, Source = NpmSource };
            var vulnNpmDep = new Dependency { Ecosystem = "npm", Name = vulnNpm.Name, Version = vulnNpm.Version, Source = NpmSource };

            var badNugetReport = new BuildCheck
            {
                Project = badProject,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Commit = "7f8e9d0c1b2a",
                Pipeline = "4096",
                Trusted = false,
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "nuget" }),
                Dependencies = new[] { blockedPkg, unauthPkg, riskPkg, cleanPkg }.Select(p => new BuildCheckDependency
                {
                    BuildCheckId = 0,
                    PackageVersionId = p.Id,
                    Ecosystem = p.Ecosystem,
                    Name = p.Name,
                    Version = p.Version,
                    Source = p.Source,
                    Trusted = p.Id == cleanPkg.Id || p.Id == riskPkg.Id
                }).ToList()
            };

            var badNpmReport = new BuildCheck
            {
                Project = badProject,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Commit = "7f8e9d0c1b2a",
                Pipeline = "4097",
                Trusted = false,
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "npm" }),
                GraphJson = JsonSerializer.Serialize(new DependencyReportGraph
                {
                    Manifests =
                    [
                        new DependencyGraphNode { Project = "web/package.json", Ecosystem = "npm", Target = "npm", Id = "root", Kind = "root", Children = ["pkg:direct"] },
                        new DependencyGraphNode { Project = "web/package.json", Ecosystem = "npm", Target = "npm", Id = "pkg:direct", Kind = "package", Package = directNpmDep, Children = ["pkg:vuln"] },
                        new DependencyGraphNode { Project = "web/package.json", Ecosystem = "npm", Target = "npm", Id = "pkg:vuln", Kind = "package", Package = vulnNpmDep, Children = [] }
                    ]
                }),
                Dependencies = new[] { directNpm, vulnNpm }.Select(p => new BuildCheckDependency
                {
                    BuildCheckId = 0,
                    PackageVersionId = p.Id,
                    Ecosystem = p.Ecosystem,
                    Name = p.Name,
                    Version = p.Version,
                    Source = p.Source,
                    Trusted = p.Id == directNpm.Id
                }).ToList()
            };

            var goodNugetReport = new BuildCheck
            {
                Project = goodProject,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Commit = "112233445566",
                Pipeline = "4098",
                Trusted = true,
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "nuget" }),
                Dependencies =
                [
                    new BuildCheckDependency
                    {
                        BuildCheckId = 0,
                        PackageVersionId = cleanPkg.Id,
                        Ecosystem = cleanPkg.Ecosystem,
                        Name = cleanPkg.Name,
                        Version = cleanPkg.Version,
                        Source = cleanPkg.Source,
                        Trusted = true
                    }
                ]
            };

            db.BuildChecks.AddRange(badNugetReport, badNpmReport, goodNugetReport);
            await db.SaveChangesAsync();
            createdCheckIds.AddRange([badNugetReport.Id, badNpmReport.Id, goodNugetReport.Id]);
        }

        try
        {
            // 1. Dashboard -> 1-click "Non-compliant projects" CTA -> Projects list with quick filters
            await NavigateAsync("/Dashboard/Index");
            var nonCompliantCta = Page.Locator("a.btn-danger", new() { HasTextString = "Non-compliant projects" });
            await Expect(nonCompliantCta).ToBeVisibleAsync();
            await nonCompliantCta.ClickAsync();
            await Expect(Page).ToHaveURLAsync(new Regex("filter=issues", RegexOptions.IgnoreCase));
            await Expect(Page.Locator(".s360-quick-filters")).ToBeVisibleAsync();
            await Expect(Page.Locator(".s360-project-card", new() { HasTextString = badProject })).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("01-projects-list-light.png");

            // 2. Open non-compliant project -> exception-first diagnosis panel at top
            await Page.Locator("a.s360-project-card", new() { HasTextString = badProject }).First.ClickAsync();
            await Expect(Page.Locator(".s360-diagnosis-panel")).ToBeVisibleAsync();
            await Expect(Page.Locator(".s360-diagnosis-panel")).ToContainTextAsync("Blocking issues (3)");
            await Expect(Page.Locator(".s360-issue-card")).ToHaveCountAsync(3);
            await Expect(Page.Locator(".s360-diagnosis-panel")).ToContainTextAsync($"web/package.json \u2192 ui-kit-{suffix}@3.1.0 \u2192 minimatch-demo-{suffix}@9.0.3");
            await Expect(Page.Locator(".s360-risk-accepted-panel")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("02-project-diagnosis-light.png");

            // 3. Diagnosis category filter pills work live in DOM
            await Page.Locator("[data-diagnosis-filter='cve']").ClickAsync();
            await Expect(Page.Locator(".s360-issue-card:visible")).ToHaveCountAsync(1);
            await Expect(Page.Locator(".s360-issue-card:visible")).ToContainTextAsync("CVE-2026-55001");

            await Page.Locator("[data-diagnosis-filter='unauthorized']").ClickAsync();
            await Expect(Page.Locator(".s360-issue-card:visible")).ToHaveCountAsync(1);
            await Expect(Page.Locator(".s360-issue-card:visible")).ToContainTextAsync($"CsvExporter.{suffix}@1.4.0");
            await CaptureIfRequestedAsync("03-project-diagnosis-filtered-light.png");

            await Page.Locator("[data-diagnosis-filter='all']").ClickAsync();
            await Expect(Page.Locator(".s360-issue-card:visible")).ToHaveCountAsync(3);

            // 4. Expand lazy Mermaid dependency graph -> renders non-zero SVG
            var graphDisclosure = Page.Locator("details.s360-graph-disclosure");
            await Expect(graphDisclosure).ToBeVisibleAsync();
            await graphDisclosure.Locator("> summary").ClickAsync();
            var svg = graphDisclosure.Locator(".s360-graph-canvas svg").First;
            await Expect(svg).ToBeVisibleAsync(new() { Timeout = 10000 });
            var svgBox = await svg.BoundingBoxAsync();
            Assert.IsNotNull(svgBox);
            Assert.IsTrue(svgBox.Width > 20 && svgBox.Height > 20,
                $"Expected rendered Mermaid SVG to have non-zero bounding box, got {svgBox.Width}x{svgBox.Height}.");

            // 5. Expand All reported dependencies -> live package filter + issues-only toggle
            var depsDisclosure = Page.Locator("details.s360-all-deps-disclosure");
            await depsDisclosure.Locator("> summary").ClickAsync();
            var searchInput = depsDisclosure.Locator("[data-project-package-filter]");
            await Expect(searchInput).ToBeVisibleAsync();
            await searchInput.FillAsync("minimatch-demo");
            await Expect(depsDisclosure.Locator("[data-package-search]:visible")).ToHaveCountAsync(1);
            await searchInput.FillAsync("");
            await depsDisclosure.Locator("[data-project-package-only-issues]").CheckAsync();
            await Expect(depsDisclosure.Locator("[data-package-search]:visible")).ToHaveCountAsync(3);
            await CaptureIfRequestedAsync("04-project-graph-and-deps-light.png");

            // 6. Click "Request this package" -> prefilled /DependencyRequests/Create
            var requestBtn = Page.Locator(".s360-issue-card a", new() { HasTextString = "Request this package" }).First;
            await Expect(requestBtn).ToBeVisibleAsync();
            await requestBtn.ClickAsync();
            await Expect(Page).ToHaveURLAsync(new Regex("/DependencyRequests/Create", RegexOptions.IgnoreCase));
            await Expect(Page.Locator("input[name='project']")).ToHaveValueAsync(badProject);
            await Expect(Page.Locator("textarea[name='directPackages']")).ToHaveValueAsync($"CsvExporter.{suffix}@1.4.0");

            // 7. Dark mode screenshots (1440px desktop + 430px mobile) + healthy project view
            await Page.EvaluateAsync("() => fetch('/api/switch-theme', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ theme: 'dark' }), credentials: 'same-origin' })");
            await NavigateAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(badProject));
            await Expect(Page.Locator(".s360-diagnosis-panel")).ToBeVisibleAsync();
            await Expect(Page.Locator("html")).ToHaveAttributeAsync("data-bs-theme", "dark");
            await CaptureIfRequestedAsync("05-project-diagnosis-dark.png");

            await Page.SetViewportSizeAsync(430, 900);
            await Expect(Page.Locator(".s360-diagnosis-panel")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("06-project-diagnosis-mobile-dark.png");

            await Page.SetViewportSizeAsync(1440, 900);
            await NavigateAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(goodProject));
            await Expect(Page.Locator(".s360-diagnosis-healthy")).ToBeVisibleAsync();
            await Expect(Page.Locator(".s360-diagnosis-healthy")).ToContainTextAsync("No blocking compliance issues");
            await CaptureIfRequestedAsync("07-project-healthy-dark.png");

            Assert.AreEqual(0, pageErrors.Count, "Unexpected page errors: " + string.Join("; ", pageErrors));
        }
        finally
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var matches = await db.VulnerabilityMatches
                .Where(m => createdPackageIds.Contains(m.PackageVersionId) || createdVulnIds.Contains(m.VulnerabilityId))
                .ToListAsync();
            db.VulnerabilityMatches.RemoveRange(matches);

            var checks = await db.BuildChecks
                .Include(c => c.Dependencies)
                .Where(c => createdCheckIds.Contains(c.Id))
                .ToListAsync();
            db.BuildChecks.RemoveRange(checks);

            var rules = await db.Rules.Where(r => createdRuleIds.Contains(r.Id)).ToListAsync();
            db.Rules.RemoveRange(rules);

            var vulns = await db.Vulnerabilities.Where(v => createdVulnIds.Contains(v.Id)).ToListAsync();
            db.Vulnerabilities.RemoveRange(vulns);

            var packages = await db.PackageVersions.Where(p => createdPackageIds.Contains(p.Id)).ToListAsync();
            db.PackageVersions.RemoveRange(packages);

            await db.SaveChangesAsync();
        }
    }

    private async Task CaptureIfRequestedAsync(string fileName)
    {
        var dir = Environment.GetEnvironmentVariable("S360_VISUAL_CAPTURE_DIR");
        if (string.IsNullOrWhiteSpace(dir)) return;
        Directory.CreateDirectory(dir);
        await Page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = Path.Combine(dir, fileName),
            FullPage = true
        });
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
