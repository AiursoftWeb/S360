using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Aiursoft.S360.Entities;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class StatusClarityTests : TestBase
{
    private readonly string _prefix = "statusclarity-" + Guid.NewGuid().ToString("N");

    [TestCleanup]
    public override async Task CleanServer()
    {
        if (Server != null)
        {
            using var scope = Server.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildCheckDependencies.RemoveRange(await db.BuildCheckDependencies.Where(d => d.Name.StartsWith(_prefix)).ToListAsync());
            db.BuildChecks.RemoveRange(await db.BuildChecks.Where(c => c.Project == "company/" + _prefix).ToListAsync());
            db.Vulnerabilities.RemoveRange(await db.Vulnerabilities.Where(v => v.PackageName.StartsWith(_prefix)).ToListAsync());
            db.PackageVersions.RemoveRange(await db.PackageVersions.Where(v => v.Name.StartsWith(_prefix)).ToListAsync());
            db.Rules.RemoveRange(await db.Rules.Where(r => r.PackagePattern.StartsWith(_prefix)).ToListAsync());
            await db.SaveChangesAsync();
        }
        await base.CleanServer();
    }

    [TestMethod]
    [DataRow("nuget", "https://nupkg.aiursoft.com/v3/index.json")]
    [DataRow("npm", "https://nopkg.aiursoft.com/npm")]
    public async Task RangeOnlyProductionReportShowsVulnerabilityAndAuthorizationMismatchAcrossPages(string ecosystem, string source)
    {
        await LoginAsAdmin();
        var name = _prefix;
        var project = "company/" + name;
        int ruleId;
        int beforeRules;
        int beforeReports;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            configuration[ecosystem == "nuget" ? "SupplyChain:NuGetSources:9" : "SupplyChain:NpmSources:9"] = source;
            var rule = new PackageRule { Ecosystem = ecosystem, PackagePattern = name, Version = "2.*", Source = source,
                Status = RuleStatus.Approved, RequestedAtUtc = DateTime.UtcNow.AddDays(-1) };
            db.Rules.Add(rule);
            db.PackageVersions.Add(new PackageVersion { Ecosystem = ecosystem, Name = name, Version = "2.0.0", Source = source });
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = ecosystem, PackageName = name, SourceId = "GHSA-" + name,
                RawAffectedJson = JsonSerializer.Serialize(new[] { new
                { package = new { ecosystem = ecosystem == "nuget" ? "NuGet" : "npm", name }, versions = new[] { "1.0.0" } } })
            });
            // An unapproved report need not have a linked PackageVersion record.
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project, RunId = Guid.NewGuid().ToString("N"), BatchCount = 1, ScannedProjectCount = 1,
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = ecosystem }),
                Dependencies = [new BuildCheckDependency { BuildCheckId = 0, PackageVersionId = null, Ecosystem = ecosystem, Name = name,
                    Version = "1.0.0", Source = source }]
            });
            await db.SaveChangesAsync();
            ruleId = rule.Id;
            beforeRules = await db.Rules.CountAsync();
            beforeReports = await db.BuildChecks.CountAsync();
        }
        foreach (var path in new[]
        {
            $"/VulnerabilityAudit/Index?ecosystem={ecosystem}&package={name}",
            $"/SupplyChain/RuleDetails/{ruleId}",
            $"/SupplyChain/PackageDetails?ruleId={ruleId}",
            $"/SupplyChain/Index?tab=projects&scope=baseline&ecosystem={ecosystem}&project={Uri.EscapeDataString(project)}"
        })
        {
            using var response = await Http.GetAsync(path);
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "data-state=\"production-affected\"", path);
            StringAssert.Contains(html, "data-state=\"unauthorized\"", path);
            StringAssert.Contains(html, "data-authorization=\"outside\"", path);
            StringAssert.Contains(html, "data-observed-version=\"1.0.0\"", path);
            StringAssert.Contains(html, "data-admission=\"denied\"", path);
            StringAssert.Contains(html, source, path);
            StringAssert.Contains(html, "will not repair an existing deployment", path);
        }
        using var verify = Server!.Services.CreateScope();
        var stored = verify.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(beforeRules, await stored.Rules.CountAsync());
        Assert.AreEqual(beforeReports, await stored.BuildChecks.CountAsync());
        Assert.IsFalse(await stored.PackageVersions.AnyAsync(v => v.Name == name && v.Version == "1.0.0"));
    }

    [TestMethod]
    public async Task VulnerabilityPaginationMovesWholePackagesAndPreservesScope()
    {
        await LoginAsAdmin();
        var prefix = _prefix;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            for (var i = 0; i < VulnerabilityAuditViewModel.PageSize + 1; i++)
            {
                var name = prefix + "-" + i;
                db.Rules.Add(new PackageRule { Ecosystem = "npm", PackagePattern = name, Version = "*",
                    Source = "https://nopkg.aiursoft.com/npm", Status = RuleStatus.Approved });
                for (var j = 0; j < 2; j++)
                    db.Vulnerabilities.Add(new Vulnerability { Ecosystem = "npm", PackageName = name,
                        SourceId = $"GHSA-{name}-{j}", RawAffectedJson = JsonSerializer.Serialize(new[] { new
                        { package = new { ecosystem = "npm", name }, versions = new[] { "1.0.0" } } }) });
            }
            await db.SaveChangesAsync();
        }
        var seen = new HashSet<string>();
        var pages = 0;
        string? next = "/VulnerabilityAudit/Index?ecosystem=npm&scope=authorization&detailed=true";
        while (next != null)
        {
            Assert.IsTrue(++pages < 10);
            var html = await Http.GetStringAsync(next);
            var groups = Regex.Matches(html, "data-package-finding=\"([^\"]+)\"");
            Assert.IsTrue(groups.Count <= VulnerabilityAuditViewModel.PageSize);
            foreach (Match group in groups.Where(g => g.Groups[1].Value.StartsWith(prefix, StringComparison.Ordinal)))
            {
                var name = group.Groups[1].Value;
                Assert.IsTrue(seen.Add(name), "A package must not appear on multiple pages.");
                StringAssert.Contains(html, $"data-finding=\"GHSA-{name}-0\"");
                StringAssert.Contains(html, $"data-finding=\"GHSA-{name}-1\"");
            }
            var link = Regex.Match(html, "href=\"([^\"]+)\">Next</a>");
            next = link.Success ? WebUtility.HtmlDecode(link.Groups[1].Value) : null;
            if (next != null) { StringAssert.Contains(next, "scope=authorization"); StringAssert.Contains(next, "detailed=true"); }
        }
        Assert.AreEqual(VulnerabilityAuditViewModel.PageSize + 1, seen.Count);
        Assert.IsTrue(pages >= 2);
        var filtered = await Http.GetStringAsync($"/VulnerabilityAudit/Index?ecosystem=npm&scope=all&package={prefix}-0");
        Assert.HasCount(1, Regex.Matches(filtered, "data-package-finding="));
        StringAssert.Contains(filtered, $"package={prefix}-0");
    }

    [TestMethod]
    public async Task ExplanationUsesRealAdmissionAndKeepsLatestFailureAsSeparateEvidenceWarning()
    {
        using var scope = Server!.Services.CreateScope();
        await using var db = new InMemoryContext(new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("status-explanation-" + Guid.NewGuid()).Options);
        var name = "explanation-" + Guid.NewGuid().ToString("N");
        const string source = "https://nuget.aiursoft.com/v3/index.json";
        db.Rules.Add(new PackageRule { Ecosystem = "nuget", PackagePattern = name, Source = source, Version = "*",
            Status = RuleStatus.Approved, RequestedAtUtc = DateTime.UtcNow.AddDays(-1) });
        var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
        if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
        audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2);
        audit.LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-1);
        audit.LastAttemptAtUtc = DateTime.UtcNow;
        audit.LastError = "Latest refresh failed";
        await db.SaveChangesAsync();
        var dependency = new Dependency { Ecosystem = "nuget", Name = name.ToUpperInvariant(), Version = "1.0.0", Source = source };
        var service = new PackageStatusService(db, new TrustService(db), scope.ServiceProvider.GetRequiredService<IConfiguration>());
        var state = (await service.DescribeAsync([dependency])).Single();
        Assert.IsTrue(state.Authorized);
        Assert.IsTrue(state.CanAdmit, "A still-fresh successful snapshot keeps the existing admission behavior.");
        Assert.IsTrue(state.NeedsVerification, "The failed refresh must remain visible alongside the admission result.");
        audit.LastSuccessAtUtc = DateTime.UtcNow.AddHours(-13);
        await db.SaveChangesAsync();
        state = (await service.DescribeAsync([dependency])).Single();
        Assert.IsTrue(state.Authorized);
        Assert.IsFalse(state.CanAdmit);
        Assert.IsTrue(state.Admission.PendingVerification);
        Assert.IsTrue(state.NeedsVerification);
    }
}
