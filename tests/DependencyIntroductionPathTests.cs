using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Tests;

[TestClass]
public class DependencyIntroductionPathTests
{
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
