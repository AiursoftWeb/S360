using System.Net;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class ProjectDiagnosisUxTests : TestBase
{
    private const string NuGetSource = "https://nupkg.aiursoft.com/v3/index.json";
    private const string NpmSource = "https://npm.aiursoft.com";

    private static DependencyDecision Decision(Dependency dep, bool trusted, bool pending = false) => new()
    {
        Dependency = dep,
        Trusted = trusted,
        PendingVerification = pending,
        Reason = trusted ? "Approved" : "Not approved"
    };

    [TestMethod]
    public void ProjectComplianceDiagnosticsOrdersIssuesBySeverityAndExtractsShortestPaths()
    {
        var blockedDep = new Dependency { Ecosystem = "nuget", Name = "Acme.Blocked", Version = "1.0.0", Source = NuGetSource };
        var vulnDep = new Dependency { Ecosystem = "npm", Name = "vuln-leaf", Version = "2.1.0", Source = NpmSource };
        var directNpm = new Dependency { Ecosystem = "npm", Name = "web-wrapper", Version = "1.0.0", Source = NpmSource };
        var sourceDeniedDep = new Dependency { Ecosystem = "nuget", Name = "Acme.PrivateFeed", Version = "1.0.0", Source = "https://evil.example/v3/index.json" };
        var unauthDep = new Dependency { Ecosystem = "nuget", Name = "Acme.Unapproved", Version = "1.2.0", Source = NuGetSource };
        var pendingDep = new Dependency { Ecosystem = "nuget", Name = "Acme.Pending", Version = "3.0.0", Source = NuGetSource };
        var cleanDep = new Dependency { Ecosystem = "nuget", Name = "Acme.Clean", Version = "4.0.0", Source = NuGetSource };

        var blockedRule = new PackageRule { Id = 101, Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = "Acme.Blocked", Version = "1.*", Justification = "Known compromised release" };
        var otherApproved = new PackageRule { Id = 202, Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = "Acme.Unapproved", Version = "2.*", Source = NuGetSource };
        var vulnAdvisory = new Vulnerability { Id = 301, SourceId = "GHSA-aaaa-bbbb-cccc", Ecosystem = "npm", PackageName = "vuln-leaf", Aliases = "[\"CVE-2026-9999\"]", RawAffectedJson = "[]" };

        var unauthId = SolutionDependencyGraph.PackageId(unauthDep);
        var cleanId = SolutionDependencyGraph.PackageId(cleanDep);
        var blockedId = SolutionDependencyGraph.PackageId(blockedDep);

        var project = new InventoryProject
        {
            Name = "org/diag-unit",
            Reports = [new InventoryReport("nuget", 1, DateTime.UtcNow, "abc123456789", "42", true)],
            Solution = new InventorySolution
            {
                Repository = "org/diag-unit",
                CheckId = 1,
                Graph = new SolutionDependencyGraph
                {
                    SolutionPath = "App.sln",
                    Nodes =
                    [
                        new SolutionGraphNode { Id = "project:src/Web.csproj", ProjectPath = "src/Web.csproj", IsSolutionMember = true },
                        new SolutionGraphNode { Id = "project:src/Worker.csproj", ProjectPath = "src/Worker.csproj", IsSolutionMember = true },
                        new SolutionGraphNode { Id = cleanId, Package = cleanDep },
                        new SolutionGraphNode { Id = unauthId, Package = unauthDep },
                        new SolutionGraphNode { Id = blockedId, Package = blockedDep }
                    ],
                    Contexts =
                    [
                        new SolutionRestoreContext
                        {
                            ProjectPath = "src/Web.csproj",
                            Target = "net10.0",
                            Edges =
                            [
                                new() { ParentId = "project:src/Web.csproj", ChildId = unauthId },
                                new() { ParentId = "project:src/Web.csproj", ChildId = cleanId },
                                new() { ParentId = cleanId, ChildId = blockedId }
                            ]
                        },
                        new SolutionRestoreContext
                        {
                            ProjectPath = "src/Worker.csproj",
                            Target = "net10.0",
                            Edges =
                            [
                                new() { ParentId = "project:src/Worker.csproj", ChildId = cleanId },
                                new() { ParentId = cleanId, ChildId = unauthId }
                            ]
                        }
                    ]
                }
            },
            Graphs =
            [
                new InventoryGraph
                {
                    Project = "web/package.json",
                    Ecosystem = "npm",
                    Target = "npm",
                    CheckId = 2,
                    Nodes =
                    [
                        new InventoryGraphNode("root", "root", null, ["pkg:direct"], InventoryStatus.NonCompliant, null, [], [], []),
                        new InventoryGraphNode("pkg:direct", "package", directNpm, ["pkg:vuln"], InventoryStatus.Compliant, null, [], [], []),
                        new InventoryGraphNode("pkg:vuln", "package", vulnDep, [], InventoryStatus.NonCompliant, "Active CVE", ["CVE-2026-9999"], [], [])
                    ]
                }
            ],
            Versions =
            [
                new InventoryVersion
                {
                    Dependency = pendingDep,
                    Status = InventoryStatus.Compliant,
                    Reason = "Vulnerability data is stale.",
                    State = new PackageVersionState
                    {
                        Dependency = pendingDep,
                        Authorization = Decision(pendingDep, true),
                        Admission = Decision(pendingDep, false, pending: true),
                        SourcePermitted = true,
                        AuditDataUncertain = true
                    }
                },
                new InventoryVersion
                {
                    Dependency = unauthDep,
                    Status = InventoryStatus.NonCompliant,
                    Reason = "Not covered by any approved rule.",
                    State = new PackageVersionState
                    {
                        Dependency = unauthDep,
                        Authorization = Decision(unauthDep, false),
                        Admission = Decision(unauthDep, false),
                        SourcePermitted = true,
                        Rules = [otherApproved]
                    }
                },
                new InventoryVersion
                {
                    Dependency = sourceDeniedDep,
                    Status = InventoryStatus.NonCompliant,
                    Reason = "Source is not permitted.",
                    State = new PackageVersionState
                    {
                        Dependency = sourceDeniedDep,
                        Authorization = Decision(sourceDeniedDep, false),
                        Admission = Decision(sourceDeniedDep, false),
                        SourcePermitted = false
                    }
                },
                new InventoryVersion
                {
                    Dependency = vulnDep,
                    Status = InventoryStatus.NonCompliant,
                    Reason = "Affected by CVE-2026-9999.",
                    State = new PackageVersionState
                    {
                        Dependency = vulnDep,
                        Authorization = Decision(vulnDep, true),
                        Admission = Decision(vulnDep, false),
                        SourcePermitted = true,
                        BlockingAdvisories = [vulnAdvisory]
                    }
                },
                new InventoryVersion
                {
                    Dependency = blockedDep,
                    Status = InventoryStatus.NonCompliant,
                    Reason = "Blocked by absolute blocklist.",
                    State = new PackageVersionState
                    {
                        Dependency = blockedDep,
                        Authorization = Decision(blockedDep, false),
                        Admission = Decision(blockedDep, false),
                        SourcePermitted = true,
                        MatchedBlockRule = blockedRule
                    }
                },
                new InventoryVersion
                {
                    Dependency = cleanDep,
                    Status = InventoryStatus.Compliant,
                    Reason = "Approved.",
                    State = new PackageVersionState
                    {
                        Dependency = cleanDep,
                        Authorization = Decision(cleanDep, true),
                        Admission = Decision(cleanDep, true),
                        SourcePermitted = true
                    }
                }
            ]
        };

        var diagnosis = ProjectComplianceDiagnostics.Build(project);

        Assert.HasCount(5, diagnosis.BlockingIssues);
        Assert.HasCount(1, diagnosis.CompliantVersions);
        CollectionAssert.AreEqual(
            new[]
            {
                ProjectIssueSeverity.Blocklisted,
                ProjectIssueSeverity.ActiveVulnerability,
                ProjectIssueSeverity.SourceNotPermitted,
                ProjectIssueSeverity.Unauthorized,
                ProjectIssueSeverity.NeedsVerification
            },
            diagnosis.BlockingIssues.Select(i => i.Severity).ToArray());

        // Blocklisted NuGet package: transitive path from src/Web.csproj -> Acme.Clean -> Acme.Blocked
        var blockIssue = diagnosis.BlockingIssues[0];
        Assert.IsFalse(blockIssue.IsDirectDependency);
        Assert.AreEqual("src/Web.csproj \u2192 Acme.Clean@4.0.0 \u2192 Acme.Blocked@1.0.0", blockIssue.IntroductionPaths[0]);

        // Active CVE npm package: transitive path from web/package.json -> web-wrapper -> vuln-leaf
        var vulnIssue = diagnosis.BlockingIssues[1];
        Assert.IsFalse(vulnIssue.IsDirectDependency);
        CollectionAssert.AreEqual(new[] { "CVE-2026-9999" }, vulnIssue.BlockingAdvisories);
        Assert.AreEqual("web/package.json \u2192 web-wrapper@1.0.0 \u2192 vuln-leaf@2.1.0", vulnIssue.IntroductionPaths[0]);

        // Source denied package: no graph recorded -> never invent edges
        var sourceIssue = diagnosis.BlockingIssues[2];
        Assert.IsEmpty(sourceIssue.IntroductionPaths);

        // Unauthorized NuGet package: direct in Web.csproj (hopCount 2) AND transitive in Worker.csproj (hopCount 3)
        var unauthIssue = diagnosis.BlockingIssues[3];
        Assert.IsTrue(unauthIssue.IsDirectDependency);
        Assert.AreEqual(2, unauthIssue.TotalPathCount);
        Assert.AreEqual("src/Web.csproj \u2192 Acme.Unapproved@1.2.0", unauthIssue.IntroductionPaths[0]);
        Assert.AreEqual("src/Worker.csproj \u2192 Acme.Clean@4.0.0 \u2192 Acme.Unapproved@1.2.0", unauthIssue.IntroductionPaths[1]);
        Assert.HasCount(1, unauthIssue.OtherApprovedRules);
        Assert.AreEqual(202, unauthIssue.OtherApprovedRules[0].Id);
    }

    [TestMethod]
    public async Task ProjectDetailPageShowsExceptionFirstDiagnosisWithPathsAndPrefillLinks()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var projectName = $"m2diag-{suffix}/shop-app";
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
            sync.LastAttemptAtUtc = now.AddMinutes(-5);
            sync.LastSuccessfulAttemptAtUtc = now.AddMinutes(-5);
            sync.LastSuccessAtUtc = now;
            sync.LastError = null;

            var blockedPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2Blocked.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var unauthPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2Unauth.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var riskPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2Risk.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var cleanPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2Clean.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var directNpmPkg = new PackageVersion { Ecosystem = "npm", Name = $"m2-direct-{suffix}", Version = "1.0.0", Source = NpmSource, LastCheckedAtUtc = now };
            var vulnNpmPkg = new PackageVersion { Ecosystem = "npm", Name = $"m2-vuln-{suffix}", Version = "2.0.0", Source = NpmSource, LastCheckedAtUtc = now };
            db.PackageVersions.AddRange(blockedPkg, unauthPkg, riskPkg, cleanPkg, directNpmPkg, vulnNpmPkg);
            await db.SaveChangesAsync();
            createdPackageIds.AddRange([blockedPkg.Id, unauthPkg.Id, riskPkg.Id, cleanPkg.Id, directNpmPkg.Id, vulnNpmPkg.Id]);

            var cveActive = new Vulnerability
            {
                SourceId = $"GHSA-m2act-{suffix}",
                Ecosystem = "npm",
                PackageName = vulnNpmPkg.Name,
                Aliases = "[\"CVE-2026-41001\"]",
                RawAffectedJson = "[]"
            };
            var cveAccepted = new Vulnerability
            {
                SourceId = $"GHSA-m2acc-{suffix}",
                Ecosystem = "nuget",
                PackageName = riskPkg.Name,
                Aliases = "[\"CVE-2026-41002\"]",
                RawAffectedJson = "[]"
            };
            db.Vulnerabilities.AddRange(cveActive, cveAccepted);
            await db.SaveChangesAsync();
            createdVulnIds.AddRange([cveActive.Id, cveAccepted.Id]);

            db.VulnerabilityMatches.AddRange(
                new VulnerabilityMatch { PackageVersionId = vulnNpmPkg.Id, VulnerabilityId = cveActive.Id },
                new VulnerabilityMatch { PackageVersionId = riskPkg.Id, VulnerabilityId = cveAccepted.Id }
            );

            var blockRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = blockedPkg.Name, Version = "1.*", Justification = "Compromised binary" };
            var otherVersionRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = unauthPkg.Name, Version = "2.*", ExpiresAtUtc = now.AddDays(60), Justification = "2.x approved" };
            var riskApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "1.*", ExpiresAtUtc = now.AddDays(60), Justification = "Approved with risk acceptance" };
            var riskAcceptance = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "1.0.0", VulnerabilityId = cveAccepted.Id, ExpiresAtUtc = now.AddDays(30), Justification = "Mitigated at edge proxy" };
            var cleanApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = cleanPkg.Name, Version = "1.*", ExpiresAtUtc = now.AddDays(60), Justification = "Standard library" };
            var npmDirectApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "npm", Source = NpmSource, PackagePattern = directNpmPkg.Name, Version = "1.*", ExpiresAtUtc = now.AddDays(60), Justification = "Frontend helper" };
            var npmVulnApproval = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "npm", Source = NpmSource, PackagePattern = vulnNpmPkg.Name, Version = "2.*", ExpiresAtUtc = now.AddDays(60), Justification = "Transitive parser" };
            db.Rules.AddRange(blockRule, otherVersionRule, riskApproval, riskAcceptance, cleanApproval, npmDirectApproval, npmVulnApproval);
            await db.SaveChangesAsync();
            createdRuleIds.AddRange([blockRule.Id, otherVersionRule.Id, riskApproval.Id, riskAcceptance.Id, cleanApproval.Id, npmDirectApproval.Id, npmVulnApproval.Id]);

            var nugetReport = new BuildCheck
            {
                Project = projectName,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Commit = "abcdef1234567890",
                Pipeline = "9876",
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

            var directNpmDep = new Dependency { Ecosystem = "npm", Name = directNpmPkg.Name, Version = directNpmPkg.Version, Source = NpmSource };
            var vulnNpmDep = new Dependency { Ecosystem = "npm", Name = vulnNpmPkg.Name, Version = vulnNpmPkg.Version, Source = NpmSource };
            var npmReport = new BuildCheck
            {
                Project = projectName,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
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
                Dependencies = new[] { directNpmPkg, vulnNpmPkg }.Select(p => new BuildCheckDependency
                {
                    BuildCheckId = 0,
                    PackageVersionId = p.Id,
                    Ecosystem = p.Ecosystem,
                    Name = p.Name,
                    Version = p.Version,
                    Source = p.Source,
                    Trusted = p.Id == directNpmPkg.Id
                }).ToList()
            };

            db.BuildChecks.AddRange(nugetReport, npmReport);
            await db.SaveChangesAsync();
            createdCheckIds.AddRange([nugetReport.Id, npmReport.Id]);
        }

        try
        {
            await LoginAsAdmin();
            var response = await Http.GetAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(projectName));
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            var html = WebUtility.HtmlDecode(await response.Content.ReadAsStringAsync());

            // Exception-first diagnosis panel and exact blocking count (3: blocklisted, active CVE, unauthorized)
            StringAssert.Contains(html, "s360-diagnosis-panel");
            StringAssert.Contains(html, "Blocking issues (3)");
            StringAssert.Contains(html, "project-diagnosis.js");

            // Severity order: Blocklisted -> Active CVE -> Unauthorized
            var blockPos = html.IndexOf($"M2Blocked.{suffix}@1.0.0", StringComparison.Ordinal);
            var vulnPos = html.IndexOf($"m2-vuln-{suffix}@2.0.0", StringComparison.Ordinal);
            var unauthPos = html.IndexOf($"M2Unauth.{suffix}@1.0.0", StringComparison.Ordinal);
            Assert.IsTrue(blockPos > 0 && vulnPos > blockPos && unauthPos > vulnPos,
                $"Expected severity order Blocklisted < ActiveCVE < Unauthorized, got {blockPos}, {vulnPos}, {unauthPos}.");

            // Transitive npm introduction path and CVE link
            StringAssert.Contains(html, $"web/package.json \u2192 m2-direct-{suffix}@1.0.0 \u2192 m2-vuln-{suffix}@2.0.0");
            StringAssert.Contains(html, "CVE-2026-41001");

            // Unauthorized issue shows other approved rule and 1-click Request this package prefill link
            StringAssert.Contains(html, "Other approved rules for this package");
            StringAssert.Contains(html, "Request this package");
            StringAssert.Contains(html, "/DependencyRequests/Create");
            StringAssert.Contains(html, $"package=M2Unauth.{suffix}@1.0.0");

            // Active risk acceptances table
            StringAssert.Contains(html, "Active risk acceptances (1)");
            StringAssert.Contains(html, $"GHSA-m2acc-{suffix}");

            // Preserved sections: ecosystem strip, graph disclosure, full deps disclosure, README badge, coverage disclaimer
            StringAssert.Contains(html, "s360-ecosystem-strip");
            StringAssert.Contains(html, "s360-graph-disclosure");
            StringAssert.Contains(html, "s360-all-deps-disclosure");
            StringAssert.Contains(html, "README badge");
            StringAssert.Contains(html, "Status covers only the reported ecosystems.");
        }
        finally
        {
            await CleanupSeededAsync(createdCheckIds, createdRuleIds, createdVulnIds, createdPackageIds);
        }
    }

    [TestMethod]
    public async Task ProjectsListQuickFiltersRiskAcceptedFilterAndDashboardCtaWork()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var prefix = $"m2list-{suffix}/";
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
            sync.LastAttemptAtUtc = now.AddMinutes(-5);
            sync.LastSuccessfulAttemptAtUtc = now.AddMinutes(-5);
            sync.LastSuccessAtUtc = now;
            sync.LastError = null;

            var cleanPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2ListClean.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var riskPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2ListRisk.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            var badPkg = new PackageVersion { Ecosystem = "nuget", Name = $"M2ListBad.{suffix}", Version = "1.0.0", Source = NuGetSource, LastCheckedAtUtc = now };
            db.PackageVersions.AddRange(cleanPkg, riskPkg, badPkg);
            await db.SaveChangesAsync();
            createdPackageIds.AddRange([cleanPkg.Id, riskPkg.Id, badPkg.Id]);

            var riskVuln = new Vulnerability { SourceId = $"GHSA-m2list-{suffix}", Ecosystem = "nuget", PackageName = riskPkg.Name, RawAffectedJson = "[]" };
            db.Vulnerabilities.Add(riskVuln);
            await db.SaveChangesAsync();
            createdVulnIds.Add(riskVuln.Id);

            db.VulnerabilityMatches.Add(new VulnerabilityMatch { PackageVersionId = riskPkg.Id, VulnerabilityId = riskVuln.Id });

            var cleanRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = cleanPkg.Name, Version = "1.*", ExpiresAtUtc = now.AddDays(30), Justification = "Clean" };
            var riskRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.Approval, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "1.*", ExpiresAtUtc = now.AddDays(30), Justification = "Risk approved" };
            var riskAcceptRule = new PackageRule { RequestedAtUtc = now.AddDays(-1), Kind = RuleKind.RiskAcceptance, Status = RuleStatus.Approved, Ecosystem = "nuget", Source = NuGetSource, PackagePattern = riskPkg.Name, Version = "1.0.0", VulnerabilityId = riskVuln.Id, ExpiresAtUtc = now.AddDays(15), Justification = "Accepted" };
            db.Rules.AddRange(cleanRule, riskRule, riskAcceptRule);
            await db.SaveChangesAsync();
            createdRuleIds.AddRange([cleanRule.Id, riskRule.Id, riskAcceptRule.Id]);

            BuildCheck MakeCheck(string name, PackageVersion pkg, bool trusted) => new()
            {
                Project = prefix + name,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Trusted = trusted,
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "nuget" }),
                Dependencies = [new BuildCheckDependency { BuildCheckId = 0, PackageVersionId = pkg.Id, Ecosystem = pkg.Ecosystem, Name = pkg.Name, Version = pkg.Version, Source = pkg.Source, Trusted = trusted }]
            };

            var cleanCheck = MakeCheck("aaa-clean", cleanPkg, true);
            var riskCheck = MakeCheck("mmm-risk", riskPkg, true);
            var badCheck = MakeCheck("zzz-bad", badPkg, false);
            db.BuildChecks.AddRange(cleanCheck, riskCheck, badCheck);
            await db.SaveChangesAsync();
            createdCheckIds.AddRange([cleanCheck.Id, riskCheck.Id, badCheck.Id]);
        }

        try
        {
            await LoginAsAdmin();

            // 1. Projects list quick filters and non-compliant-first ordering
            var listHtml = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&query=" + Uri.EscapeDataString(prefix));
            StringAssert.Contains(listHtml, "s360-quick-filters");
            StringAssert.Contains(listHtml, "Needs attention (");
            StringAssert.Contains(listHtml, "Risk accepted (");

            var badIndex = listHtml.IndexOf(prefix + "zzz-bad", StringComparison.Ordinal);
            var cleanIndex = listHtml.IndexOf(prefix + "aaa-clean", StringComparison.Ordinal);
            Assert.IsTrue(badIndex > 0 && cleanIndex > badIndex, "Non-compliant project should sort before alphabetically earlier compliant project.");

            // 2. Risk-accepted quick filter isolates only risk-accepted projects
            var riskHtml = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&filter=risk-accepted&query=" + Uri.EscapeDataString(prefix));
            StringAssert.Contains(riskHtml, prefix + "mmm-risk");
            Assert.DoesNotContain(prefix + "aaa-clean", riskHtml);
            Assert.DoesNotContain(prefix + "zzz-bad", riskHtml);

            // 3. Healthy project shows green diagnosis summary and expanded all-deps disclosure
            var healthyHtml = await Http.GetStringAsync("/SupplyChain/Index?tab=projects&project=" + Uri.EscapeDataString(prefix + "aaa-clean"));
            StringAssert.Contains(healthyHtml, "s360-diagnosis-healthy");
            StringAssert.Contains(healthyHtml, "No blocking compliance issues");

            // 4. Dashboard header CTA points to non-compliant projects filter=issues
            var dashHtml = await Http.GetStringAsync("/Dashboard/Index");
            StringAssert.Contains(dashHtml, "Non-compliant projects (");
            StringAssert.Contains(dashHtml, "filter=issues");
        }
        finally
        {
            await CleanupSeededAsync(createdCheckIds, createdRuleIds, createdVulnIds, createdPackageIds);
        }
    }

    private async Task CleanupSeededAsync(
        List<int> checkIds,
        List<int> ruleIds,
        List<int> vulnIds,
        List<int> packageIds)
    {
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

        var matches = await db.VulnerabilityMatches
            .Where(m => packageIds.Contains(m.PackageVersionId) || vulnIds.Contains(m.VulnerabilityId))
            .ToListAsync();
        db.VulnerabilityMatches.RemoveRange(matches);

        var checks = await db.BuildChecks
            .Include(c => c.Dependencies)
            .Where(c => checkIds.Contains(c.Id))
            .ToListAsync();
        db.BuildChecks.RemoveRange(checks);

        var rules = await db.Rules.Where(r => ruleIds.Contains(r.Id)).ToListAsync();
        db.Rules.RemoveRange(rules);

        var vulns = await db.Vulnerabilities.Where(v => vulnIds.Contains(v.Id)).ToListAsync();
        db.Vulnerabilities.RemoveRange(vulns);

        var packages = await db.PackageVersions.Where(p => packageIds.Contains(p.Id)).ToListAsync();
        db.PackageVersions.RemoveRange(packages);

        await db.SaveChangesAsync();
    }
}
