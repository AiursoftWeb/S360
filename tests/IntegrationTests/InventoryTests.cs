using System.Net;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class InventoryTests : TestBase
{
    private readonly string _prefix = "inventory-" + Guid.NewGuid().ToString("N") + "/";
    private const string Source = "https://nuget.aiursoft.com/v3/index.json";

    private BuildCheck Report(string project, string? purpose, string? ecosystem,
        DateTime time, params PackageArtifact[] artifacts) => new()
    {
        Project = _prefix + project, RunId = Guid.NewGuid().ToString("N"), ScannedProjectCount = 1,
        CreatedAtUtc = time, Trusted = true,
        ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = purpose, Ecosystem = ecosystem }),
        Dependencies = artifacts.Select(a => new BuildCheckDependency
        {
            BuildCheckId = 0, PackageArtifactId = a.Id, PackageArtifact = a,
            Ecosystem = a.Ecosystem, Name = a.Name, Version = a.Version, Source = a.Source,
            Sha256 = a.Sha256, Trusted = true
        }).ToList()
    };

    private static PackageArtifact Artifact(string name, string ecosystem = "nuget") => new()
    {
        Name = name, Ecosystem = ecosystem, Version = "1.0.0",
        Source = ecosystem == "nuget" ? Source : "https://registry.npmjs.org",
        Sha256 = new string('a', 64), FirstTrustedAtUtc = DateTime.UtcNow.AddHours(-1),
        SourceVerifiedAtUtc = DateTime.UtcNow.AddHours(-1), LastCheckedAtUtc = DateTime.UtcNow
    };

    private static TrustRule Approve(PackageArtifact artifact) => new()
    {
        ApplicationId = null, SupplierId = 0, Supplier = new Supplier { Name = "Inventory supplier" },
        Ecosystem = artifact.Ecosystem, Source = artifact.Source, PackagePattern = artifact.Name,
        Version = "1.*", Status = TrustRuleStatus.Approved, ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
        Justification = "Approved to parse employee-provided documents."
    };

    private async Task<InventoryViewModel> Read(string tab = "dependencies", string scope = "baseline",
        string? query = null, string filter = "all", int page = 1, string? project = null, string ecosystem = "all")
    {
        using var serviceScope = Server!.Services.CreateScope();
        var model = new InventoryViewModel { Tab = tab, Scope = scope, Query = query ?? _prefix, Filter = filter, Page = page, CanRead = true, Project = project, Ecosystem = ecosystem };
        await serviceScope.ServiceProvider.GetRequiredService<CatalogInventoryService>().PopulateAsync(model);
        return model;
    }

    private async Task<string> ReadBadge(string project, string expected)
    {
        var response = await Http.GetAsync("/badge.svg?project=" + Uri.EscapeDataString(_prefix + project));
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual("image/svg+xml", response.Content.Headers.ContentType?.MediaType);
        Assert.AreEqual(TimeSpan.FromSeconds(60), response.Headers.CacheControl?.MaxAge);
        var svg = await response.Content.ReadAsStringAsync();
        Assert.AreEqual("S360: " + expected, System.Xml.Linq.XDocument.Parse(svg).Root!.Element(
            System.Xml.Linq.XName.Get("title", "http://www.w3.org/2000/svg"))!.Value);
        Assert.DoesNotContain(_prefix, svg);
        return svg;
    }

    [TestMethod]
    public async Task AnonymousBadgeUsesOnlyExactLatestBaselinesAndMarksIncompleteReportsPending()
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var now = DateTime.UtcNow;
            db.BuildChecks.AddRange(Report("clean", "baseline", "nuget", now),
                Report("clean-extra", "baseline", "npm", now),
                Report("review-only", "review", "nuget", now),
                Report("legacy", null, "nuget", now));
            var incomplete = Report("partial", "baseline", "nuget", now);
            incomplete.BatchCount = 2;
            db.BuildChecks.AddRange(incomplete, Report("partial", "baseline", "nuget", now.AddMinutes(-1)));
            var review = Report("clean", "review", "nuget", now.AddMinutes(1));
            review.BatchCount = 2;
            db.BuildChecks.Add(review);
            await db.SaveChangesAsync();
        }
        Assert.Contains("#4c1", await ReadBadge("clean", "compliant"));
        Assert.Contains("#dfb317", await ReadBadge("partial", "pending"));
        await ReadBadge("review-only", "unknown");
        await ReadBadge("legacy", "unknown");
        await ReadBadge("missing", "unknown");
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.GetAsync("/badge.svg")).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.GetAsync("/badge.svg?project=" + new string('a', 201))).StatusCode);
    }

    [TestMethod]
    public async Task AnonymousBadgeReevaluatesCvesWithdrawalPolicyAndFreshnessWithoutWritingData()
    {
        int artifactId, ruleId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = Artifact("Badge." + Guid.NewGuid().ToString("N"));
            var rule = Approve(artifact);
            db.TrustRules.Add(rule);
            db.BuildChecks.Add(Report("policy", "baseline", "nuget", DateTime.UtcNow, artifact));
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddHours(-2);
            await db.SaveChangesAsync();
            artifactId = artifact.Id; ruleId = rule.Id;
        }
        await ReadBadge("policy", "compliant");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.VulnerabilityMatches.Add(new VulnerabilityMatch
            {
                VulnerabilityId = 0, PackageArtifactId = artifactId,
                Vulnerability = new Vulnerability { SourceId = "CVE-2099-1234", Ecosystem = "nuget", PackageName = "Badge" }
            });
            await db.SaveChangesAsync();
        }
        Assert.Contains("#e05d44", await ReadBadge("policy", "CVE found"));
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            (await db.VulnerabilityMatches.Include(m => m.Vulnerability).SingleAsync(m => m.PackageArtifactId == artifactId)).Vulnerability.Withdrawn = true;
            (await db.TrustRules.SingleAsync(r => r.Id == ruleId)).Status = TrustRuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        await ReadBadge("policy", "non-compliant");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            (await db.TrustRules.SingleAsync(r => r.Id == ruleId)).Status = TrustRuleStatus.Approved;
            (await db.PackageArtifacts.SingleAsync(a => a.Id == artifactId)).LastCheckedAtUtc = DateTime.UtcNow.AddDays(-1);
            await db.SaveChangesAsync();
        }
        await ReadBadge("policy", "pending");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.AreEqual(1, await db.BuildChecks.CountAsync(c => c.Project == _prefix + "policy"));
            Assert.IsTrue((await db.PackageArtifacts.SingleAsync(a => a.Id == artifactId)).LastCheckedAtUtc < DateTime.UtcNow.AddHours(-12));
        }
    }

    [TestMethod]
    public async Task OpenProjectShowsCurrentGraphPolicyAndKeepsLegacyReportsFlat()
    {
        int ruleId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = Artifact("Graph.Policy." + Guid.NewGuid().ToString("N"));
            var rule = Approve(artifact);
            rule.Justification = "Read structured project configuration.";
            db.TrustRules.Add(rule);
            var report = Report("graph", "baseline", "nuget", DateTime.UtcNow, artifact);
            report.GraphJson = JsonSerializer.Serialize(new[]
            {
                new DependencyGraphNode { Project = "src/App.csproj", Ecosystem = "nuget", Id = "$root", Kind = "root", Children = ["package"] },
                new DependencyGraphNode { Project = "src/App.csproj", Ecosystem = "nuget", Id = "package",
                    Package = new Dependency { Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
                        Source = artifact.Source + "/", Sha256 = artifact.Sha256 } }
            });
            db.BuildChecks.Add(report);
            db.BuildChecks.Add(Report("legacy", "baseline", null, DateTime.UtcNow, artifact));
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
            audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow.AddSeconds(1);
            audit.LastError = null;
            await db.SaveChangesAsync(); ruleId = rule.Id;
        }
        Assert.IsTrue((await Read("projects")).Projects.All(p => p.Graphs.Count == 0));
        var opened = (await Read("projects", project: _prefix + "graph")).Projects.Single();
        Assert.IsTrue(opened.Reports.Single().HasGraph);
        var graphPackage = opened.Graphs.Single().Nodes.Single(n => n.Package != null);
        CollectionAssert.AreEquivalent(new[] { _prefix + "graph", _prefix + "legacy" }, graphPackage.Projects);
        CollectionAssert.Contains(graphPackage.Purposes, "Read structured project configuration.");
        Assert.AreEqual(InventoryStatus.Compliant, opened.Graphs.Single().Nodes.Single(n => n.Package != null).Status,
            opened.Graphs.Single().Nodes.Single(n => n.Package != null).Reason);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            (await db.TrustRules.SingleAsync(r => r.Id == ruleId)).Status = TrustRuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        opened = (await Read("projects", project: _prefix + "graph")).Projects.Single();
        Assert.AreEqual(InventoryStatus.NonCompliant, opened.Graphs.Single().Nodes.Single(n => n.Package != null).Status,
            opened.Graphs.Single().Nodes.Single(n => n.Package != null).Reason);
        var legacy = (await Read("projects", project: _prefix + "legacy")).Projects.Single();
        Assert.IsFalse(legacy.Reports.Single(r => r.Ecosystem == "nuget").HasGraph);
        Assert.AreEqual(0, legacy.Graphs.Count);
        await LoginAsAdmin();
        var html = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(_prefix + "graph"));
        StringAssert.Contains(html, "s360-graph-data");
        StringAssert.Contains(html, "dependency-graph.js");
    }

    [TestMethod]
    public async Task ProjectListsRespectReportScopeAndEcosystemWithoutLosingIncompleteReports()
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var now = DateTime.UtcNow;
            db.BuildChecks.AddRange(Report("production", "baseline", "nuget", now),
                Report("production", "review", "nuget", now.AddMinutes(1)),
                Report("proposed-only", "review", "nuget", now),
                Report("legacy-only", null, "nuget", now),
                Report("frontend-only", "baseline", "npm", now));
            var incomplete = Report("incomplete-only", "baseline", "nuget", now);
            incomplete.BatchCount = 2;
            db.BuildChecks.Add(incomplete);
            await db.SaveChangesAsync();
        }
        var baseline = await Read("projects");
        CollectionAssert.AreEquivalent(new[] { _prefix + "production", _prefix + "frontend-only", _prefix + "incomplete-only" },
            baseline.Projects.Select(p => p.Name).ToArray());
        Assert.IsTrue(baseline.Projects.Single(p => p.Name.EndsWith("incomplete-only")).Incomplete);
        Assert.AreEqual(InventoryStatus.Pending, baseline.Projects.Single(p => p.Name.EndsWith("incomplete-only")).Status);
        Assert.AreEqual(InventoryStatus.Compliant, baseline.Projects.Single(p => p.Name.EndsWith("production")).Status);
        Assert.AreEqual(0, (await Read("projects", scope: "review")).ProjectCount);
        Assert.AreEqual(_prefix + "legacy-only", (await Read("projects", scope: "history")).Projects.Single().Name);
        Assert.AreEqual(0, (await Read("projects", project: _prefix + "proposed-only")).Total);
        var nuget = await Read("projects", ecosystem: "nuget");
        CollectionAssert.AreEquivalent(new[] { _prefix + "production", _prefix + "incomplete-only" },
            nuget.Projects.Select(p => p.Name).ToArray());
        Assert.AreEqual(2, nuget.Total);
        var allNuget = await Read("projects", ecosystem: "nuget", query: "");
        Assert.AreEqual(allNuget.Total, allNuget.ProjectCount);
        await LoginAsAdmin();
        var html = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&scope=baseline&ecosystem=nuget&query=" + Uri.EscapeDataString(_prefix));
        Assert.DoesNotContain(_prefix + "proposed-only", html);
        Assert.DoesNotContain(_prefix + "legacy-only", html);
        Assert.DoesNotContain(_prefix + "frontend-only", html);
        StringAssert.Contains(html, "npm: not included in this audit.");
        StringAssert.Contains(html, "Status covers only the reported ecosystems.");
        StringAssert.Contains(html, "No complete snapshot is available; current coverage is not verified");
    }

    [TestMethod]
    public async Task ProjectStatusUsesSelectedEcosystemsAndPreservesFailuresInReportedPackages()
    {
        var nugetName = "NuGet.Approved." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var nuget = Artifact(nugetName);
            var npm = Artifact("npm-unapproved-" + Guid.NewGuid().ToString("N"), "npm");
            db.TrustRules.Add(Approve(nuget));
            db.BuildChecks.AddRange(Report("backend", "baseline", "nuget", DateTime.UtcNow, nuget),
                Report("mixed", "baseline", "nuget", DateTime.UtcNow, nuget),
                Report("mixed", "baseline", "npm", DateTime.UtcNow, npm));
            var partial = Report("mixed", "baseline", "npm", DateTime.UtcNow.AddMinutes(1));
            partial.BatchCount = 2;
            db.BuildChecks.Add(partial);
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow.AddSeconds(1);
            await db.SaveChangesAsync();
        }
        var all = await Read("projects");
        Assert.AreEqual(InventoryStatus.Compliant, all.Projects.Single(p => p.Name.EndsWith("backend")).Status);
        Assert.AreEqual(InventoryStatus.NonCompliant, all.Projects.Single(p => p.Name.EndsWith("mixed")).Status);
        var selected = await Read("projects", ecosystem: "nuget", filter: "compliant");
        Assert.AreEqual(2, selected.Total);
        Assert.IsTrue(selected.Projects.All(p => p.Status == InventoryStatus.Compliant && !p.Incomplete));
        Assert.IsTrue(selected.Projects.All(p => p.Reports.All(r => r.Ecosystem == "nuget")));
        Assert.AreEqual(InventoryStatus.NonCompliant, (await Read("projects", ecosystem: "npm")).Projects.Single().Status);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = await db.PackageArtifacts.SingleAsync(a => a.Name == nugetName);
            db.VulnerabilityMatches.Add(new VulnerabilityMatch
            {
                PackageArtifactId = artifact.Id, VulnerabilityId = 0,
                Vulnerability = new Vulnerability { Ecosystem = "nuget", PackageName = artifact.Name,
                    SourceId = "GHSA-inventory-scope-" + Guid.NewGuid().ToString("N") }
            });
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(2, (await Read("projects", ecosystem: "nuget", filter: "cve")).Total);
        Assert.IsTrue((await Read("projects", ecosystem: "nuget")).Projects.All(p => p.Status == InventoryStatus.NonCompliant));
    }

    [TestMethod]
    public async Task InventoryUsesLatestCompleteBaselinesAndPreservesOtherEcosystems()
    {
        var now = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var old = Artifact("Old.Package");
            var current = Artifact("Current.Package");
            var proposed = Artifact("Proposed.Package");
            var incomplete = Artifact("Incomplete.Package");
            var npm = Artifact("frontend", "npm");
            db.BuildChecks.AddRange(Report("web", "baseline", null, now.AddMinutes(-5), old, npm),
                Report("web", "baseline", "nuget", now.AddMinutes(-4), current),
                Report("web", "review", "nuget", now.AddMinutes(-3), proposed),
                Report("web", null, "nuget", now.AddMinutes(-2), old));
            var partial = Report("web", "baseline", "nuget", now.AddMinutes(-1), incomplete);
            partial.BatchCount = 2;
            db.BuildChecks.Add(partial);
            await db.SaveChangesAsync();
        }
        var baseline = await Read();
        CollectionAssert.AreEquivalent(new[] { "Current.Package", "frontend" }, baseline.Packages.Select(p => p.Name).ToArray());
        var projects = await Read("projects");
        Assert.IsTrue(projects.Projects.Single().Incomplete);
        Assert.AreNotEqual(InventoryStatus.Compliant, projects.Projects.Single().Status);
        Assert.AreEqual(0, (await Read(scope: "review")).PackageCount);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildChecks.Add(Report("web", "baseline", "nuget", now));
            await db.SaveChangesAsync();
        }
        CollectionAssert.AreEqual(new[] { "frontend" }, (await Read()).Packages.Select(p => p.Name).ToArray());
        Assert.IsFalse((await Read("projects")).Projects.Single().Incomplete);
    }

    [TestMethod]
    public async Task InventoryReassessesExpiryRevocationCvesAndAuditFreshnessWithoutWrites()
    {
        int ruleId;
        int artifactId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = Artifact("Current.Policy");
            var rule = Approve(artifact);
            db.TrustRules.Add(rule);
            db.BuildChecks.Add(Report("backend", "baseline", null, DateTime.UtcNow, artifact));
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
            audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow.AddSeconds(1);
            await db.SaveChangesAsync(); ruleId = rule.Id; artifactId = artifact.Id;
        }
        Assert.AreEqual(InventoryStatus.Compliant, (await Read()).Packages.Single().Status);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var rule = await db.TrustRules.SingleAsync(r => r.Id == ruleId);
            rule.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(InventoryStatus.NonCompliant, (await Read()).Packages.Single().Status);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var rule = await db.TrustRules.SingleAsync(r => r.Id == ruleId);
            rule.ExpiresAtUtc = DateTime.UtcNow.AddDays(1);
            rule.Status = TrustRuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(InventoryStatus.NonCompliant, (await Read()).Packages.Single().Status);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            (await db.TrustRules.SingleAsync(r => r.Id == ruleId)).Status = TrustRuleStatus.Approved;
            var audit = await db.VulnerabilitySyncStates.SingleAsync();
            audit.LastAttemptAtUtc = DateTime.UtcNow.AddDays(-1);
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddDays(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow.AddDays(-1);
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(InventoryStatus.Pending, (await Read()).Packages.Single().Status);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.VulnerabilityMatches.Add(new VulnerabilityMatch
            {
                PackageArtifactId = artifactId, VulnerabilityId = 0, Active = true,
                Vulnerability = new Vulnerability { Ecosystem = "nuget", PackageName = "Current.Policy", SourceId = "GHSA-inventory-test", Aliases = "[\"CVE-2099-10001\"]" }
            });
            await db.SaveChangesAsync();
        }
        var finding = (await Read(filter: "cve")).Packages.Single();
        Assert.AreEqual(InventoryStatus.NonCompliant, finding.Status);
        CollectionAssert.AreEqual(new[] { "CVE-2099-10001" }, finding.Versions.Single().Advisories);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.IsTrue((await db.BuildChecks.SingleAsync(c => c.Project == _prefix + "backend")).Trusted, "Reading current status must not rewrite the old verdict.");
        }
    }

    [TestMethod]
    public async Task InventorySearchesUsesAndReasonsAndPaginatesAllResults()
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            for (var i = 0; i < 25; i++)
            {
                var artifact = Artifact($"Catalog.Package{i:00}");
                var rule = Approve(artifact);
                rule.Justification = "Pagination purpose: parse employee-provided documents.";
                db.TrustRules.Add(rule);
                db.BuildChecks.Add(Report("Project-" + i, "baseline", null, DateTime.UtcNow, artifact));
            }
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(20, (await Read()).Packages.Count);
        var secondPage = await Read(page: 2);
        Assert.AreEqual(5, secondPage.Packages.Count);
        Assert.IsTrue(secondPage.Summary.PackageCount >= 25);
        Assert.IsTrue(secondPage.Summary.ProjectCount >= 25);
        Assert.AreEqual(secondPage.Summary.PackageCount, (await Read(query: "Project-24")).Summary.PackageCount,
            "Search and pagination must not shrink company-wide totals.");
        Assert.AreEqual(25, (await Read(query: "Pagination purpose")).Total);
        Assert.AreEqual("Catalog.Package24", (await Read(query: "Project-24")).Packages.Single().Name);
        Assert.AreEqual(0, (await Read(query: "not-present")).Total);
        await LoginAsAdmin();
        var overview = await Http.GetStringAsync("/SupplyChain/Index?query=Project-24");
        StringAssert.Contains(overview, "s360-project-card");
        StringAssert.Contains(overview, "Project-24");
        Assert.DoesNotContain("s360-graph-data", overview);
        var html = await Http.GetStringAsync("/SupplyChain/Index?tab=dependencies&query=Project-24");
        StringAssert.Contains(html, "Catalog.Package24");
        StringAssert.Contains(html, "Pagination purpose: parse employee-provided documents.");
        StringAssert.Contains(html, "No project purpose recorded");
        StringAssert.Contains(html, "s360-inventory-tabs");
        var packageDetails = await Http.GetStringAsync("/SupplyChain/Index?tab=dependencies&query=Catalog.Package24");
        StringAssert.Contains(packageDetails, "Why is it needed?");
        StringAssert.Contains(packageDetails, "Recorded in these projects");
        StringAssert.Contains(packageDetails, "open=\"open\"");
        var projects = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(_prefix + "Project-24"));
        StringAssert.Contains(projects, "Catalog.Package24");
        StringAssert.Contains(projects, "Dependency relationships were not recorded");
        using var invalid = await Http.GetAsync("/SupplyChain/Index?tab=invalid");
        Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [TestMethod]
    public async Task CompanySummaryUsesCurrentBaselinesAndLinksRisksToProjects()
    {
        var options = new DbContextOptionsBuilder<InMemoryContext>()
            .UseInMemoryDatabase("s360-company-summary-" + Guid.NewGuid()).Options;
        await using var db = new InMemoryContext(options);
        var service = new CatalogInventoryService(db, new TrustService(db),
            Server!.Services.GetRequiredService<IConfiguration>());
        var empty = new InventoryViewModel();
        await service.PopulateAsync(empty);
        Assert.AreEqual(0, empty.Summary.ProjectCount);
        Assert.AreEqual(0, empty.Summary.PackageCount);
        Assert.IsNull(empty.Summary.LatestReportUtc);
        var now = DateTime.UtcNow;
        var safe = Artifact("Company.Safe");
        var vulnerable = Artifact("Company.Vulnerable");
        var unknown = Artifact("Company.Unknown");
        var reviewOnly = Artifact("Company.ReviewOnly");
        var removed = Artifact("Company.Removed");
        db.TrustRules.AddRange(Approve(safe), Approve(vulnerable), Approve(unknown));
        unknown.SourceVerifiedAtUtc = null;
        db.BuildChecks.Add(Report("safe", "baseline", "nuget", now, safe));
        db.BuildChecks.Add(Report("affected", "baseline", "nuget", now, safe, vulnerable));
        db.BuildChecks.Add(Report("unknown", "baseline", "nuget", now, unknown));
        db.BuildChecks.Add(Report("review-only", "review", "nuget", now, reviewOnly));
        db.BuildChecks.Add(Report("safe", "baseline", "nuget", now.AddDays(-1), removed));
        var incomplete = Report("incomplete", "baseline", "nuget", now);
        incomplete.BatchCount = 2;
        db.BuildChecks.Add(incomplete);
        db.VulnerabilityMatches.Add(new VulnerabilityMatch
        {
            PackageArtifactId = 0, PackageArtifact = vulnerable, VulnerabilityId = 0, Active = true,
            Vulnerability = new Vulnerability { Ecosystem = "nuget", PackageName = vulnerable.Name,
                SourceId = "GHSA-company-test", Aliases = "[\"CVE-2099-10002\"]" }
        });
        var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
        if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
        audit.LastSuccessfulAttemptAtUtc = now.AddMinutes(-1);
        audit.LastSuccessAtUtc = now.AddSeconds(1);
        await db.SaveChangesAsync();
        var model = new InventoryViewModel();
        await service.PopulateAsync(model);
        var summary = model.Summary;
        Assert.AreEqual(4, summary.ProjectCount);
        Assert.AreEqual(3, summary.PackageCount, "Shared packages count once; review and superseded versions are excluded.");
        Assert.AreEqual(1, summary.VulnerablePackageCount);
        Assert.AreEqual(1, summary.VulnerableProjectCount);
        Assert.AreEqual(1, summary.ProjectStatuses[InventoryStatus.Compliant]);
        Assert.AreEqual(1, summary.ProjectStatuses[InventoryStatus.NonCompliant]);
        Assert.AreEqual(2, summary.ProjectStatuses[InventoryStatus.Pending]);
        Assert.AreEqual(1, summary.PackageStatuses[InventoryStatus.Compliant]);
        Assert.AreEqual(1, summary.PackageStatuses[InventoryStatus.NonCompliant]);
        Assert.AreEqual(1, summary.PackageStatuses[InventoryStatus.Pending]);
        Assert.AreEqual("Company.Vulnerable", summary.PriorityPackages.First().Name);
        Assert.AreEqual(_prefix + "affected", summary.PriorityProjects.First().Name);
    }

    [TestMethod]
    public async Task InventoryDoesNotExposeProjectsOrReasonsWithoutReadPermission()
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = Artifact("Confidential.Package");
            db.TrustRules.Add(Approve(artifact));
            db.BuildChecks.Add(Report("Confidential-Project", "baseline", null, DateTime.UtcNow, artifact));
            await db.SaveChangesAsync();
        }
        await RegisterAndLoginAsync();
        var html = await Http.GetStringAsync("/SupplyChain/Index?query=Confidential");
        Assert.DoesNotContain("Confidential-Project", html);
        Assert.DoesNotContain("Confidential.Package", html);
        Assert.DoesNotContain("Approved to parse employee-provided documents.", html);
        StringAssert.Contains(html, "requires supply-chain read permission");
    }
}
