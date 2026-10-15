using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;

namespace Aiursoft.S360.Tests;

[TestClass]
public class PackageResolutionGraphTests
{
    [TestMethod]
    public void NuGetReviewProjectPinsDirectVersionExactly()
    {
        var project = PackageResolutionService.CreateNuGetProject([new DirectPackage("A", "1.0.0")]);
        var reference = project.Descendants("PackageReference").Single();
        Assert.AreEqual("A", (string?)reference.Attribute("Include"));
        Assert.AreEqual("[1.0.0]", (string?)reference.Attribute("Version"));
        Assert.AreEqual("false", (string?)project.Descendants("NuGetAudit").Single());
    }

    [TestMethod]
    public void NuGetReviewConfigUsesOnlySelectedSource()
    {
        var config = PackageResolutionService.CreateNuGetConfig("https://nuget.aiursoft.com/v3/index.json");
        var sources = config.Descendants("packageSources").Single();
        Assert.AreEqual("clear", sources.Elements().First().Name.LocalName);
        Assert.AreEqual("https://nuget.aiursoft.com/v3/index.json",
            (string?)sources.Elements("add").Single().Attribute("value"));
        Assert.ThrowsExactly<ArgumentException>(() => PackageResolutionService.CreateNuGetConfig("http://nuget.example.com"));
    }

    [TestMethod]
    public void NuGetGraphIncludesTransitivePackageAndRoot()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"targets":{"net10.0":{"A/1.0.0":{"type":"package","dependencies":{"B":"2.0.0"}},"B/2.0.0":{"type":"package"}}}}
                """);
            var a = Package("nuget", "A", "1.0.0");
            var b = Package("nuget", "B", "2.0.0");
            var edges = PackageResolutionService.ReadNuGetEdges(file, [a, b], [new DirectPackage("A", "1.0.0")]);
            Assert.IsTrue(edges.Any(e => e.Parent == null && e.Child == a));
            Assert.IsTrue(edges.Any(e => e.Parent == a && e.Child == b));
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NuGetGraphRejectsRootWhenRestoreSelectsHigherVersion()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"targets":{"net10.0":{"A/1.2.0":{"type":"package","dependencies":{"B":"2.0.0"}},"B/2.0.0":{"type":"package"}}}}
                """);
            var a = Package("nuget", "A", "1.2.0");
            var b = Package("nuget", "B", "2.0.0");
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                PackageResolutionService.ReadNuGetEdges(file, [a, b], [new DirectPackage("A", "1.0.0")]));
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NpmGraphResolvesNestedPackageFromNearestNodeModules()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"packages":{"":{"dependencies":{"a":"1.0.0"}},"node_modules/a":{"version":"1.0.0","dependencies":{"b":"2.0.0"}},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}
                """);
            var a = Package("npm", "a", "1.0.0");
            var b = Package("npm", "b", "2.0.0");
            var edges = PackageResolutionService.ReadNpmEdges(file, [a, b], [new DirectPackage("a", "1.0.0")]);
            Assert.IsTrue(edges.Any(e => e.Parent == null && e.Child == a));
            Assert.IsTrue(edges.Any(e => e.Parent == a && e.Child == b));
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NpmGraphIncludesInstalledRootPeerDependencies()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"packages":{"":{"dependencies":{"a":"1.0.0"},"peerDependencies":{"peer":"2.0.0"}},
                "node_modules/a":{"version":"1.0.0"},"node_modules/peer":{"version":"2.0.0"}}}
                """);
            var a = Package("npm", "a", "1.0.0");
            var peer = Package("npm", "peer", "2.0.0");
            var edges = PackageResolutionService.ReadNpmEdges(file, [a, peer],
                [new DirectPackage("a", "1.0.0"), new DirectPackage("peer", "2.0.0")]);
            Assert.IsTrue(edges.Any(e => e.Parent == null && e.Child == peer));
            PackageResolutionService.ValidateGraph([a, peer], edges);
            var application = new DependencyApplication
            {
                Ecosystem = "npm", Source = a.Source, ResolutionContext = "npm; test",
                DirectPackages = """[{"Name":"a","Version":"1.0.0"},{"Name":"peer","Version":"2.0.0"}]"""
            };
            Assert.HasCount(64, ReportFingerprint.Compute(application,
                new ResolutionReport([a, peer], edges, [], application.ResolutionContext)));
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void ReportRejectsOrphanPackagesButAllowsReachableCycles()
    {
        var a = Package("npm", "a", "1.0.0");
        var b = Package("npm", "b", "1.0.0");
        var orphan = Package("npm", "orphan", "1.0.0");
        var reachableCycle = new List<ResolutionEdge>
        {
            new(null, a), new(a, b), new(b, a)
        };
        PackageResolutionService.ValidateGraph([a, b], reachableCycle);
        var error = Assert.ThrowsExactly<InvalidOperationException>(() =>
            PackageResolutionService.ValidateGraph([a, b, orphan], reachableCycle));
        StringAssert.Contains(error.Message, "no introduction path");
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            PackageResolutionService.ValidateGraph([a], [new ResolutionEdge(null, b)]));
    }

    [TestMethod]
    public void ReportRejectsDifferentArchiveBytesForOnePackageIdentity()
    {
        var first = Package("nuget", "Example", "1.0.0");
        var changed = Package("nuget", "example", "1.0.0");
        changed.Sha256 = new string('b', 64);
        var edges = new List<ResolutionEdge> { new(null, first), new(null, changed) };
        var error = Assert.ThrowsExactly<InvalidOperationException>(() =>
            PackageResolutionService.ValidateGraph([first, changed], edges));
        StringAssert.Contains(error.Message, "conflicting archive hashes");

        var application = new DependencyApplication
        {
            Ecosystem = "nuget", Source = first.Source, ResolutionContext = "net10.0; any runtime",
            DirectPackages = """[{"Name":"Example","Version":"1.0.0"}]""",
            Packages = [
                new ApplicationPackage { ApplicationId = 0, PackageArtifactId = 1, IsDirect = true,
                    PackageArtifact = Artifact(1, first) },
                new ApplicationPackage { ApplicationId = 0, PackageArtifactId = 2, IsDirect = true,
                    PackageArtifact = Artifact(2, changed) }
            ],
            Edges = [
                new ApplicationEdge { ApplicationId = 0, ParentPackageId = null, ChildPackageId = 1 },
                new ApplicationEdge { ApplicationId = 0, ParentPackageId = null, ChildPackageId = 2 }
            ]
        };
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
    }

    [TestMethod]
    public void SavedReportFingerprintMatchesResolvedGraphAndDetectsGraphChanges()
    {
        var root = Package("nuget", "A", "1.0.0");
        var child = Package("nuget", "B", "2.0.0");
        var report = new ResolutionReport([root, child],
            [new ResolutionEdge(null, root), new ResolutionEdge(root, child)], [], "net10.0; any runtime");
        var application = new DependencyApplication
        {
            Ecosystem = "nuget", Source = root.Source, ResolutionContext = report.Context,
            DirectPackages = """[{"Name":"A","Version":"1.0.0"}]""",
            Packages = [
                new ApplicationPackage { ApplicationId = 0, PackageArtifactId = 1, IsDirect = true,
                    PackageArtifact = Artifact(1, root) },
                new ApplicationPackage { ApplicationId = 0, PackageArtifactId = 2,
                    PackageArtifact = Artifact(2, child) }
            ],
            Edges = [
                new ApplicationEdge { ApplicationId = 0, ParentPackageId = null, ChildPackageId = 1 },
                new ApplicationEdge { ApplicationId = 0, ParentPackageId = 1, ChildPackageId = 2 }
            ]
        };
        var original = ReportFingerprint.Compute(application, report);
        Assert.AreEqual(original, ReportFingerprint.ComputePersisted(application));

        application.ResolutionContext = "net10.0; linux-x64";
        Assert.AreNotEqual(original, ReportFingerprint.ComputePersisted(application));
        application.ResolutionContext = report.Context;
        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Sha256 = new string('b', 64);
        Assert.AreNotEqual(original, ReportFingerprint.ComputePersisted(application));
        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Sha256 = child.Sha256;
        Assert.AreEqual(original, ReportFingerprint.ComputePersisted(application));

        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Source =
            "https://other.example.com";
        var changedSource = Assert.ThrowsExactly<InvalidOperationException>(() =>
            ReportFingerprint.ComputePersisted(application));
        StringAssert.Contains(changedSource.Message, "outside the requested ecosystem or source");
        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Source = child.Source;
        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Ecosystem = "npm";
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
        application.Packages.Single(p => p.PackageArtifactId == 2).PackageArtifact.Ecosystem = "nuget";
        Assert.AreEqual(original, ReportFingerprint.ComputePersisted(application));

        application.DirectPackages = """[{"Name":"B","Version":"2.0.0"}]""";
        var changedRequest = Assert.ThrowsExactly<InvalidOperationException>(() =>
            ReportFingerprint.ComputePersisted(application));
        StringAssert.Contains(changedRequest.Message, "do not match the request");
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.Compute(application, report));
        application.DirectPackages = "not JSON";
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
        application.DirectPackages = """[{"Name":"A","Version":"1.0.0"}]""";
        Assert.AreEqual(original, ReportFingerprint.ComputePersisted(application));

        var cyclicApplication = WithGraph(application, edges: application.Edges.Append(new ApplicationEdge { ApplicationId = 0, ParentPackageId = 2, ChildPackageId = 1 }));
        Assert.AreNotEqual(original, ReportFingerprint.ComputePersisted(cyclicApplication));

        var orphanApplication = WithGraph(cyclicApplication, packages: cyclicApplication.Packages.Append(new ApplicationPackage
        {
            ApplicationId = 0,
            PackageArtifactId = 3, PackageArtifact = Artifact(3, Package("nuget", "Orphan", "1.0.0"))
        }));
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(orphanApplication));
    }

    [TestMethod]
    public void SavedApplicationPathsExplainIndirectDependenciesWithoutLooping()
    {
        var root = Artifact(1, Package("npm", "root", "1.0.0"));
        var indirect = Artifact(2, Package("npm", "indirect", "2.0.0"));
        var paths = ApplicationPaths.Build([
            new ApplicationEdge { ApplicationId = 0, ParentPackageId = null, ChildPackageId = 1 },
            new ApplicationEdge { ApplicationId = 0, ParentPackageId = 1, ChildPackageId = 2 },
            new ApplicationEdge { ApplicationId = 0, ParentPackageId = 2, ChildPackageId = 1 }
        ], new Dictionary<int, PackageArtifact> { [1] = root, [2] = indirect });
        Assert.AreEqual("root", paths[1]);
        Assert.AreEqual("root → indirect", paths[2]);
    }

    private static DependencyApplication WithGraph(DependencyApplication application,
        IEnumerable<ApplicationPackage>? packages = null, IEnumerable<ApplicationEdge>? edges = null) => new()
    {
        Ecosystem = application.Ecosystem, Source = application.Source,
        ResolutionContext = application.ResolutionContext, DirectPackages = application.DirectPackages,
        Packages = packages ?? application.Packages, Edges = edges ?? application.Edges
    };

    private static PackageArtifact Artifact(int id, Dependency dependency) => new()
    {
        Id = id, Ecosystem = dependency.Ecosystem, Name = dependency.Name, Version = dependency.Version,
        Source = dependency.Source, Sha256 = dependency.Sha256
    };

    private static Dependency Package(string ecosystem, string name, string version) => new()
    {
        Ecosystem = ecosystem, Name = name, Version = version,
        Source = "https://registry.example.com", Sha256 = new string('a', 64)
    };
}
