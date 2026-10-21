using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Tests;

[TestClass]
public class DependencyIntroductionPathTests
{
    [TestMethod]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Nodes\":null}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Contexts\":null}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Nodes\":[null]}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Contexts\":[null]}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Contexts\":[{\"ProjectPath\":\"App.csproj\",\"Target\":\"net10.0\",\"Edges\":null}]}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Contexts\":[{\"ProjectPath\":\"App.csproj\",\"Target\":\"net10.0\",\"ProjectTargets\":null}]}")]
    [DataRow("{\"SolutionPath\":\"App.sln\",\"Contexts\":[{\"ProjectPath\":\"App.csproj\",\"Target\":\"net10.0\",\"Edges\":[null]}]}")]
    public void SolutionGraphRejectsNullValuesFromExternalJson(string json)
    {
        var graph = System.Text.Json.JsonSerializer.Deserialize<SolutionDependencyGraph>(json)!;
        Assert.IsNotNull(graph.ValidatePart());
    }

    [TestMethod]
    public void LargeSolutionBatchesReassembleWithoutDroppingDependenciesOrContextEdges()
    {
        var packages = Enumerable.Range(0, 1100).Select(i =>
            Package("nuget", $"Example.P{i}", "1.0.0", "https://nuget.example/v3/index.json")).ToList();
        var graph = new SolutionDependencyGraph
        {
            SolutionPath = "Product.sln",
            Nodes = [new() { Id = "project:App.csproj", ProjectPath = "App.csproj", IsSolutionMember = true }],
            Contexts = [new() { ProjectPath = "App.csproj", Target = "net10.0" }]
        };
        foreach (var package in packages)
        {
            var id = SolutionDependencyGraph.PackageId(package);
            graph.Nodes.Add(new SolutionGraphNode { Id = id, Package = package });
            graph.Contexts[0].Edges.Add(new SolutionDependencyEdge { ParentId = "project:App.csproj", ChildId = id });
        }
        var requests = DependencyReportGraph.CreateBatches(new ScanReport(packages, [], 1) { SolutionGraph = graph },
            new CheckContext { Repository = "company/example", SolutionPath = "Product.sln", Purpose = "baseline", Ecosystem = "nuget" },
            "company/example//Product.sln");
        Assert.IsTrue(requests.Count > 1);
        Assert.IsTrue(requests.All(r => System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(r).Length < 3 * 1024 * 1024));
        var parts = requests.SkipLast(1).Select(r => DependencyReportGraph.Read(DependencyReportGraph.Serialize(r)!)).ToList();
        Assert.IsNull(DependencyReportGraph.Validate(requests.Last(), parts,
            requests.SelectMany(r => r.Dependencies).ToList(), true));
        var assembled = SolutionDependencyGraph.Assemble(requests.Select(r => r.SolutionGraph!).ToList());
        Assert.HasCount(1101, assembled.Nodes);
        Assert.HasCount(1100, assembled.Contexts.Single().Edges);
    }

    [TestMethod]
    public void BatchedSolutionMustHaveConsistentFrameworksAndExactlyTheCheckedPackages()
    {
        var package = Package("nuget", "Example", "1.0.0", "https://nuget.example/v3/index.json");
        var id = SolutionDependencyGraph.PackageId(package);
        var first = new SolutionDependencyGraph
        {
            SolutionPath = "Example.sln",
            Nodes = [new() { Id = "project:App.csproj", ProjectPath = "App.csproj", IsSolutionMember = true }],
            Contexts = [new() { ProjectPath = "App.csproj", Target = "net10.0",
                ProjectTargets = new() { ["App.csproj"] = "net10.0" } }]
        };
        var last = new SolutionDependencyGraph
        {
            SolutionPath = "Example.sln",
            Nodes = [new() { Id = id, Package = package }],
            Contexts = [new() { ProjectPath = "App.csproj", Target = "net10.0",
                ProjectTargets = new() { ["App.csproj"] = "net10.0" },
                Edges = [new() { ParentId = "project:App.csproj", ChildId = id }] }]
        };
        var request = new CheckRequest { SolutionGraph = last, ScannedProjectCount = 1 };
        var prior = new DependencyReportGraph { Solution = first };
        Assert.IsNull(DependencyReportGraph.Validate(request, [prior], [package], true));
        Assert.IsNotNull(DependencyReportGraph.Validate(request, [prior], [], true));
        last.Contexts[0].ProjectTargets["App.csproj"] = "net9.0";
        StringAssert.Contains(DependencyReportGraph.Validate(request, [prior], [package], true)!, "disagree");
        last.Contexts[0].ProjectTargets["App.csproj"] = "net10.0";
        last.SolutionPath = "Other.sln";
        Assert.IsNotNull(DependencyReportGraph.Validate(request, [prior], [package], true));
        last.SolutionPath = "Example.sln";
        last.Contexts[0].Edges[0].ChildId = "missing";
        StringAssert.Contains(DependencyReportGraph.Validate(request, [prior], [package], true)!, "existing nodes");
    }

    [TestMethod]
    public void SolutionCollectorUsesReferencedFilePathInsteadOfNuGetProjectName()
    {
        var directory = Path.Combine(Path.GetTempPath(), "s360-solution-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var assets = Path.Combine(directory, "assets.json");
            var app = Path.Combine(directory, "App", "App.csproj");
            var library = Path.Combine(directory, "Library", "Library.csproj");
            File.WriteAllText(assets, System.Text.Json.JsonSerializer.Serialize(new
            {
                targets = new Dictionary<string, object>
                {
                    ["net10.0"] = new Dictionary<string, object>
                    {
                        ["Renamed.Package/1.0.0"] = new { type = "project", dependencies = new Dictionary<string, string> { ["Child"] = "1.0.0" } },
                        ["Child/1.0.0"] = new { type = "package" }
                    }
                },
                libraries = new Dictionary<string, object>
                {
                    ["Renamed.Package/1.0.0"] = new { type = "project", msbuildProject = "../Library/Library.csproj" },
                    ["Child/1.0.0"] = new { type = "package" }
                },
                project = new
                {
                    frameworks = new Dictionary<string, object> { ["net10.0"] = new { } },
                    restore = new
                    {
                        projectPath = app,
                        frameworks = new Dictionary<string, object>
                        {
                            ["net10.0"] = new { projectReferences = new Dictionary<string, object> { [library] = new { projectPath = library } } }
                        }
                    }
                }
            }));
            var package = Package("nuget", "Child", "1.0.0", "https://nuget.example/v3/index.json");
            var graph = new SolutionDependencyGraph
            {
                SolutionPath = "Example.sln",
                Nodes = [new() { Id = "project:App/App.csproj", ProjectPath = "App/App.csproj", IsSolutionMember = true },
                    new() { Id = "project:Library/Library.csproj", ProjectPath = "Library/Library.csproj" }]
            };
            SolutionGraphCollector.AddProject(graph, assets, [package], directory);
            var context = graph.Contexts.Single();
            Assert.AreEqual("App/App.csproj", context.ProjectPath);
            Assert.IsTrue(context.Edges.Any(e => e.ParentId == "project:App/App.csproj" && e.ChildId == "project:Library/Library.csproj"));
            Assert.IsTrue(context.Edges.Any(e => e.ParentId == "project:Library/Library.csproj" && e.ChildId == SolutionDependencyGraph.PackageId(package)));
            Assert.IsFalse(graph.Nodes.Any(n => n.Id.Contains("Renamed.Package")));
            var paths = graph.PathsTo(new HashSet<string> { SolutionDependencyGraph.PackageId(package) });
            Assert.HasCount(1, paths);
            Assert.HasCount(2, paths[0].Edges);
        }
        finally { Directory.Delete(directory, true); }
    }

    [TestMethod]
    public void WholeSolutionFindsVulnerableSiblingWithoutSelectingItsProject()
    {
        var safe = Package("nuget", "Shared", "2.0.0", "https://nuget.example/v3/index.json");
        var vulnerable = Package("nuget", "Shared", "1.0.0", safe.Source);
        var safeId = SolutionDependencyGraph.PackageId(safe);
        var vulnerableId = SolutionDependencyGraph.PackageId(vulnerable);
        var graph = new SolutionDependencyGraph
        {
            SolutionPath = "Company.sln",
            Nodes = [
                new() { Id = "project:Safe.csproj", ProjectPath = "Safe.csproj", IsSolutionMember = true },
                new() { Id = "project:SqlServer.csproj", ProjectPath = "SqlServer.csproj", IsSolutionMember = true },
                new() { Id = safeId, Package = safe }, new() { Id = vulnerableId, Package = vulnerable }
            ],
            Contexts = [
                new() { ProjectPath = "Safe.csproj", Target = "net10.0", Edges = [
                    new() { ParentId = "project:Safe.csproj", ChildId = safeId }] },
                new() { ProjectPath = "SqlServer.csproj", Target = "net10.0", Edges = [
                    new() { ParentId = "project:SqlServer.csproj", ChildId = vulnerableId }] }
            ]
        };
        Assert.IsNull(graph.Validate([safe, vulnerable], 2));
        Assert.AreNotEqual(safeId, vulnerableId);
        var paths = graph.PathsTo(new HashSet<string> { vulnerableId });
        Assert.HasCount(1, paths);
        Assert.AreEqual("SqlServer.csproj", paths[0].ProjectPath);
        Assert.AreEqual(vulnerableId, paths[0].Edges.Single().ChildId);

        graph.Contexts.RemoveAt(1);
        Assert.IsNotNull(graph.Validate([safe, vulnerable], 2));
    }

    [TestMethod]
    public void SolutionPathsDoNotMixFrameworksThroughASharedPackage()
    {
        var shared = Package("nuget", "Shared", "1.0.0", "https://nuget.example/v3/index.json");
        var vulnerable = Package("nuget", "Affected", "1.0.0", shared.Source);
        var sharedId = SolutionDependencyGraph.PackageId(shared);
        var vulnerableId = SolutionDependencyGraph.PackageId(vulnerable);
        var graph = new SolutionDependencyGraph
        {
            SolutionPath = "Company.sln",
            Nodes = [new() { Id = "project:App.csproj", ProjectPath = "App.csproj", IsSolutionMember = true },
                new() { Id = sharedId, Package = shared }, new() { Id = vulnerableId, Package = vulnerable }],
            Contexts = [
                new() { ProjectPath = "App.csproj", Target = "net9.0", Edges = [
                    new() { ParentId = "project:App.csproj", ChildId = sharedId }] },
                new() { ProjectPath = "App.csproj", Target = "net10.0", Edges = [
                    new() { ParentId = "project:App.csproj", ChildId = sharedId },
                    new() { ParentId = sharedId, ChildId = vulnerableId }] }
            ]
        };
        Assert.IsNull(graph.Validate([shared, vulnerable], 1));
        var paths = graph.PathsTo(new HashSet<string> { vulnerableId });
        Assert.HasCount(1, paths);
        Assert.AreEqual("net10.0", paths[0].Target);
        Assert.HasCount(2, paths[0].Edges);

        graph.Contexts[1].Edges.RemoveAt(0);
        StringAssert.Contains(graph.Validate([shared, vulnerable], 1)!, "path");
    }

    [TestMethod]
    public void NuGetPathExplainsTransitiveIntroduction()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"targets":{"net10.0":{
                  "Parent/1.0.0":{"type":"package","dependencies":{"Child":"2.0.0"}},
                  "Child/2.0.0":{"type":"package"}}},
                 "project":{"frameworks":{"net10.0":{"dependencies":{"Parent":{}}}}}}
                """);
            var parent = Package("nuget", "Parent", "1.0.0", "https://nuget.example/v3/index.json");
            var child = Package("nuget", "Child", "2.0.0", "https://nuget.example/v3/index.json");
            var paths = new Dictionary<string, List<string>>();
            DependencyIntroductionPaths.AddNuGet(file, [parent, child], "Sample.csproj", paths);
            Assert.AreEqual("Sample.csproj → Parent@1.0.0 → Child@2.0.0",
                paths[DependencyIntroductionPaths.Identity(child)].Single());
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NuGetPathIncludesProjectReference()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"targets":{"net10.0":{
                  "Library/1.0.0":{"type":"project","dependencies":{"Child":"2.0.0"}},
                  "Child/2.0.0":{"type":"package"}}}}
                """);
            var child = Package("nuget", "Child", "2.0.0", "https://nuget.example/v3/index.json");
            var paths = new Dictionary<string, List<string>>();
            DependencyIntroductionPaths.AddNuGet(file, [child], "App.csproj", paths);
            Assert.AreEqual("App.csproj → Library (project reference) → Child@2.0.0",
                paths[DependencyIntroductionPaths.Identity(child)].Single());
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NpmPathExplainsHoistedTransitiveIntroduction()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-introduction-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "parent"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "child"));
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            File.WriteAllText(lockFile, """
                {"packages":{
                  "":{"dependencies":{"parent":"1.0.0"}},
                  "node_modules/parent":{"version":"1.0.0",
                    "resolved":"https://npm.example/parent-1.0.0.tgz",
                    "dependencies":{"child":"2.0.0"}},
                  "node_modules/child":{"version":"2.0.0",
                    "resolved":"https://npm.example/child-2.0.0.tgz"}}}
                """);
            var parent = Package("npm", "parent", "1.0.0", "https://npm.example");
            var child = Package("npm", "child", "2.0.0", "https://npm.example");
            var paths = new Dictionary<string, List<string>>();
            DependencyIntroductionPaths.AddNpm(lockFile, [parent, child], "package.json", paths);
            Assert.AreEqual("package.json → parent@1.0.0 → child@2.0.0",
                paths[DependencyIntroductionPaths.Identity(child)].Single());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [TestMethod]
    public void NpmPathShowsAliasWithoutChangingRealPackageIdentity()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-alias-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "friendly"));
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            File.WriteAllText(lockFile, """
                {"packages":{
                  "":{"dependencies":{"friendly":"npm:real-package@1.0.0"}},
                  "node_modules/friendly":{"name":"real-package","version":"1.0.0",
                    "resolved":"https://npm.example/real-package-1.0.0.tgz"}}}
                """);
            var real = Package("npm", "real-package", "1.0.0", "https://npm.example");
            var paths = new Dictionary<string, List<string>>();
            DependencyIntroductionPaths.AddNpm(lockFile, [real], "package.json", paths);
            Assert.AreEqual("package.json → friendly (alias for real-package@1.0.0)",
                paths[DependencyIntroductionPaths.Identity(real)].Single());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [TestMethod]
    public void NpmPathsDoNotConfuseSamePackageFromDifferentSources()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-source-path-" + Guid.NewGuid().ToString("N"));
        foreach (var parent in new[] { "left", "right" })
        {
            Directory.CreateDirectory(Path.Combine(root, "node_modules", parent));
            Directory.CreateDirectory(Path.Combine(root, "node_modules", parent, "node_modules", "child"));
        }
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            File.WriteAllText(lockFile, """
                {"packages":{
                  "":{"dependencies":{"left":"1.0.0","right":"1.0.0"}},
                  "node_modules/left":{"version":"1.0.0","dependencies":{"child":"2.0.0"}},
                  "node_modules/right":{"version":"1.0.0","dependencies":{"child":"2.0.0"}},
                  "node_modules/left/node_modules/child":{"version":"2.0.0",
                    "resolved":"https://left.example/child-2.0.0.tgz"},
                  "node_modules/right/node_modules/child":{"version":"2.0.0",
                    "resolved":"https://right.example/child-2.0.0.tgz"}}}
                """);
            var left = Package("npm", "child", "2.0.0", "https://left.example");
            var right = Package("npm", "child", "2.0.0", "https://right.example");
            var paths = new Dictionary<string, List<string>>();
            DependencyIntroductionPaths.AddNpm(lockFile, [left, right], "package.json", paths);
            Assert.AreEqual("package.json → left@1.0.0 → child@2.0.0",
                paths[DependencyIntroductionPaths.Identity(left)].Single());
            Assert.AreEqual("package.json → right@1.0.0 → child@2.0.0",
                paths[DependencyIntroductionPaths.Identity(right)].Single());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [TestMethod]
    public void NuGetGraphsKeepEveryParentAndRestoreTargetWithoutInventingEdges()
    {
        var file = Path.GetTempFileName();
        try
        {
            File.WriteAllText(file, """
                {"targets":{
                  "net10.0":{"Parent/1.0.0":{"type":"package","dependencies":{"Child":"2.0.0"}},
                    "Other/1.0.0":{"type":"package","dependencies":{"Child":"2.0.0"}},
                    "Child/2.0.0":{"type":"package"},"Isolated/1.0.0":{"type":"package"}},
                  "net10.0/linux-x64":{"Child/2.0.0":{"type":"package"}}},
                 "project":{"frameworks":{"net10.0":{"dependencies":{"Parent":{},"Other":{}}}}}}
                """);
            var packages = new[] { Package("nuget", "Parent", "1.0.0", "https://nuget.example"),
                Package("nuget", "Other", "1.0.0", "https://nuget.example"),
                Package("nuget", "Child", "2.0.0", "https://nuget.example"),
                Package("nuget", "Isolated", "1.0.0", "https://nuget.example") };
            var graph = new List<DependencyGraphNode>();
            DependencyIntroductionPaths.AddNuGet(file, packages, "src/App.csproj", [], graph);
            Assert.IsNull(DependencyGraphNode.Validate(graph, packages, "nuget", true));
            Assert.AreEqual(2, graph.Count(n => n.Kind == "root"));
            var first = graph.Where(n => n.Target == "net10.0").ToList();
            CollectionAssert.AreEquivalent(new[] { "Parent", "Other" }, first.Single(n => n.Kind == "root").Children);
            Assert.AreEqual(2, first.Count(n => n.Children.Contains("Child")));
            Assert.IsFalse(first.Any(n => n.Children.Contains("Isolated")));
        }
        finally { File.Delete(file); }
    }

    [TestMethod]
    public void NpmGraphsPreserveNestedVersionsSharedParentsCyclesAndMissingOptionalPackages()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-graph-" + Guid.NewGuid().ToString("N"));
        foreach (var path in new[] { "node_modules/left", "node_modules/right", "node_modules/child", "node_modules/right/node_modules/child" })
            Directory.CreateDirectory(Path.Combine(root, path));
        try
        {
            var file = Path.Combine(root, "package-lock.json");
            File.WriteAllText(file, """
                {"packages":{
                  "":{"dependencies":{"left":"1.0.0","right":"1.0.0"}},
                  "node_modules/left":{"version":"1.0.0","resolved":"https://npm.example/left.tgz",
                    "dependencies":{"child":"1.0.0"},"optionalDependencies":{"absent":"1.0.0"}},
                  "node_modules/right":{"version":"1.0.0","resolved":"https://npm.example/right.tgz",
                    "dependencies":{"left":"1.0.0","child":"2.0.0"}},
                  "node_modules/child":{"version":"1.0.0","resolved":"https://npm.example/child1.tgz",
                    "dependencies":{"left":"1.0.0"}},
                  "node_modules/right/node_modules/child":{"version":"2.0.0","resolved":"https://npm.example/child2.tgz"},
                  "node_modules/absent":{"version":"1.0.0","resolved":"https://npm.example/absent.tgz"}}}
                """);
            var packages = new[] { Package("npm", "left", "1.0.0", "https://npm.example"),
                Package("npm", "right", "1.0.0", "https://npm.example"),
                Package("npm", "child", "1.0.0", "https://npm.example"), Package("npm", "child", "2.0.0", "https://npm.example") };
            var graph = new List<DependencyGraphNode>();
            DependencyIntroductionPaths.AddNpm(file, packages, "web/package.json", [], graph);
            Assert.IsNull(DependencyGraphNode.Validate(graph, packages, "npm", true));
            Assert.AreEqual(5, graph.Count);
            CollectionAssert.AreEquivalent(new[] { "node_modules/left", "node_modules/right/node_modules/child" },
                graph.Single(n => n.Id == "node_modules/right").Children);
            CollectionAssert.AreEqual(new[] { "node_modules/left" }, graph.Single(n => n.Id == "node_modules/child").Children);
            Assert.AreEqual("2.0.0", graph.Single(n => n.Id == "node_modules/right/node_modules/child").Package!.Version);
            Assert.IsFalse(graph.Any(n => n.Id.Contains("absent")));
        }
        finally { Directory.Delete(root, true); }
    }

    private static Dependency Package(string ecosystem, string name, string version, string source) => new()
    {
        Ecosystem = ecosystem, Name = name, Version = version, Source = source, Sha256 = new string('a', 64)
    };
}
