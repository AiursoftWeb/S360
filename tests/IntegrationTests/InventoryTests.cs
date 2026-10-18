using System.Net;
using System.Text.Json;
using Aiursoft.S360.Entities;
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
        string? query = null, string filter = "all", int page = 1, string? project = null)
    {
        using var serviceScope = Server!.Services.CreateScope();
        var model = new InventoryViewModel { Tab = tab, Scope = scope, Query = query ?? _prefix, Filter = filter, Page = page, CanRead = true, Project = project };
        await serviceScope.ServiceProvider.GetRequiredService<CatalogInventoryService>().PopulateAsync(model);
        return model;
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
        CollectionAssert.AreEqual(new[] { "Proposed.Package" }, (await Read(scope: "review")).Packages.Select(p => p.Name).ToArray());
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
        Assert.AreEqual(5, (await Read(page: 2)).Packages.Count);
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
        var projects = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(_prefix + "Project-24"));
        StringAssert.Contains(projects, "Catalog.Package24");
        StringAssert.Contains(projects, "Dependency relationships were not recorded");
        using var invalid = await Http.GetAsync("/SupplyChain/Index?tab=invalid");
        Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
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
