using System.Net;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Tests;

[TestClass]
public class DependencyScannerTests
{
    [TestMethod]
    [DataRow("nuget")]
    [DataRow("npm")]
    public async Task EcosystemScopeChecksOnlySelectedProjects(string ecosystem)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-scope-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var project = Path.Combine(root, "Empty.csproj");
            var assets = Path.Combine(root, "obj", "project.assets.json");
            await File.WriteAllTextAsync(project, "<Project />");
            await File.WriteAllTextAsync(assets, JsonSerializer.Serialize(new
            {
                targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                packageFolders = new { }, libraries = new { },
                project = new { restore = new { projectPath = project } }
            }));
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"), """{"name":"sample"}""");
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"),
                """{"lockfileVersion":3,"packages":{"":{}}}""");
            using var http = new HttpClient(new FixedHandler([]));
            Assert.AreEqual(2, (await DependencyScanner.ScanDetailedAsync(root, http)).ScannedProjectCount);
            if (ecosystem == "nuget")
                await File.WriteAllTextAsync(Path.Combine(root, "package.json"), "uninstalled npm project");
            else File.Delete(assets);
            var report = await DependencyScanner.ScanDetailedAsync(root, http, ecosystem: ecosystem);
            Assert.AreEqual(1, report.ScannedProjectCount);
            Assert.HasCount(0, report.Dependencies);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task DiscoverySkipsGeneratedDirectoriesBeforeFindingProjects()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-pruned-discovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var project = Path.Combine(root, "Sample.csproj");
            await File.WriteAllTextAsync(project, "<Project />");
            Directory.CreateDirectory(Path.Combine(root, "obj"));
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { }, libraries = new { },
                    project = new { restore = new { projectPath = project } }
                }));
            foreach (var ignored in new[] { "node_modules", "bin", "obj", ".git", "TestResults" })
            {
                var child = Path.Combine(root, ignored, "nested");
                Directory.CreateDirectory(child);
                await File.WriteAllTextAsync(Path.Combine(child, "package.json"), "not valid JSON");
                await File.WriteAllTextAsync(Path.Combine(child, "Fake.csproj"), "<Project />");
            }
            using var client = new HttpClient(new FixedHandler([]));
            var report = await DependencyScanner.ScanDetailedAsync(root, client);
            Assert.AreEqual(1, report.ScannedProjectCount);
            Assert.AreEqual(0, report.Dependencies.Count);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task DiscoveryRejectsDirectoryLinksThatCouldHideProjectsOutsideRoot()
    {
        if (OperatingSystem.IsWindows()) return;
        var parent = Path.Combine(Path.GetTempPath(), "s360-linked-discovery-" + Guid.NewGuid().ToString("N"));
        var root = Path.Combine(parent, "root");
        var external = Path.Combine(parent, "external");
        var link = Path.Combine(root, "linked");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(external);
        try
        {
            Directory.CreateSymbolicLink(link, external);
            using var client = new HttpClient(new FixedHandler([]));
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
            StringAssert.Contains(error.Message, "Directory links cannot be scanned completely");
        }
        finally
        {
            if (Directory.Exists(link)) Directory.Delete(link);
            Directory.Delete(parent, true);
        }
    }

    [TestMethod]
    [DataRow(".fsproj")]
    [DataRow(".vbproj")]
    public async Task NuGetProjectTypesAreDiscovered(string extension)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-project-type-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "Sample" + extension), "<Project />");
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { }, libraries = new { },
                    project = new { restore = new { projectPath = Path.Combine(root, "Sample" + extension) } }
                }));
            using var client = new HttpClient(new FixedHandler([]));
            var report = await DependencyScanner.ScanDetailedAsync(root, client);
            Assert.AreEqual(0, report.Dependencies.Count);
            Assert.AreEqual(1, report.ScannedProjectCount);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetProjectReferenceInsideScanRootIsIncluded()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-project-refs-" + Guid.NewGuid().ToString("N"));
        var main = Path.Combine(root, "Main");
        var library = Path.Combine(root, "Lib");
        Directory.CreateDirectory(Path.Combine(main, "obj"));
        Directory.CreateDirectory(Path.Combine(library, "obj"));
        try
        {
            var mainProject = Path.Combine(main, "Main.csproj");
            var libraryProject = Path.Combine(library, "Lib.csproj");
            await File.WriteAllTextAsync(mainProject, "<Project />");
            await File.WriteAllTextAsync(libraryProject, "<Project />");
            await File.WriteAllTextAsync(Path.Combine(main, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { },
                    libraries = new Dictionary<string, object>
                    {
                        ["Lib/1.0.0"] = new { type = "project", msbuildProject = "../Lib/Lib.csproj" }
                    },
                    project = new { restore = new { projectPath = mainProject } }
                }));
            await File.WriteAllTextAsync(Path.Combine(library, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { }, libraries = new { },
                    project = new { restore = new { projectPath = libraryProject } }
                }));
            using var client = new HttpClient(new FixedHandler([]));
            var report = await DependencyScanner.ScanDetailedAsync(root, client);
            Assert.AreEqual(2, report.ScannedProjectCount);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetProjectReferenceOutsideScanRootFailsClosed()
    {
        var parent = Path.Combine(Path.GetTempPath(), "s360-external-project-" + Guid.NewGuid().ToString("N"));
        var main = Path.Combine(parent, "Main");
        var library = Path.Combine(parent, "Lib");
        Directory.CreateDirectory(Path.Combine(main, "obj"));
        Directory.CreateDirectory(library);
        try
        {
            var mainProject = Path.Combine(main, "Main.csproj");
            await File.WriteAllTextAsync(mainProject, "<Project />");
            await File.WriteAllTextAsync(Path.Combine(library, "Lib.csproj"), "<Project />");
            await File.WriteAllTextAsync(Path.Combine(main, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { },
                    libraries = new Dictionary<string, object>
                    {
                        ["Lib/1.0.0"] = new { type = "project", msbuildProject = "../Lib/Lib.csproj" }
                    },
                    project = new { restore = new { projectPath = mainProject } }
                }));
            using var client = new HttpClient(new FixedHandler([]));
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(main, client));
            StringAssert.Contains(error.Message, "outside the scanned projects");
        }
        finally { Directory.Delete(parent, true); }
    }

    [TestMethod]
    public async Task LegacyNuGetProjectFailsClosed()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-legacy-nuget-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "Sample.csproj"), "<Project />");
            await File.WriteAllTextAsync(Path.Combine(root, "packages.config"), "<packages />");
            using var client = new HttpClient(new FixedHandler([]));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetScanRejectsRestoreOutputFromAnotherProject()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-stale-assets-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "Current.csproj"), "<Project />");
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new { project = new { restore = new { projectPath = Path.Combine(root, "Other.csproj") } } }));
            using var client = new HttpClient(new FixedHandler([]));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetScanRejectsProjectOrCentralVersionsChangedAfterRestore()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-stale-input-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var manifest = Path.Combine(root, "Current.csproj");
            var assets = Path.Combine(root, "obj", "project.assets.json");
            var central = Path.Combine(root, "Directory.Packages.props");
            await File.WriteAllTextAsync(manifest, "<Project />");
            await File.WriteAllTextAsync(assets, JsonSerializer.Serialize(new
            {
                project = new { restore = new { projectPath = manifest } }
            }));
            var later = File.GetLastWriteTimeUtc(assets).AddMinutes(1);
            File.SetLastWriteTimeUtc(manifest, later);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                DependencyScanner.ValidateNuGetAssetsForProject(manifest, assets));
            File.SetLastWriteTimeUtc(manifest, File.GetLastWriteTimeUtc(assets).AddMinutes(-1));
            await File.WriteAllTextAsync(central, "<Project />");
            File.SetLastWriteTimeUtc(central, later);
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                DependencyScanner.ValidateNuGetAssetsForProject(manifest, assets));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetPackageOnlyInSecondTargetCannotBeSkipped()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-multi-target-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var assets = Path.Combine(root, "project.assets.json");
            await File.WriteAllTextAsync(assets,
                """{"targets":{"net10.0":{},"net10.0/linux-x64":{"Unreviewed/1.0.0":{"type":"package"}}},"packageFolders":{}}""");
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => DependencyScanner.ReadNuGetAsync(assets));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    [DataRow("../outside/1.0.0")]
    [DataRow("bad\\name/1.0.0")]
    [DataRow("Example/..")]
    [DataRow("Example/C:1.0.0")]
    public async Task NuGetRestoreIdentityCannotEscapePackageCache(string packageKey)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-nuget-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var assets = Path.Combine(root, "project.assets.json");
            await File.WriteAllTextAsync(assets, JsonSerializer.Serialize(new
            {
                targets = new Dictionary<string, object>
                {
                    ["net10.0"] = new Dictionary<string, object>
                    {
                        [packageKey] = new { type = "package" }
                    }
                },
                packageFolders = new Dictionary<string, object> { [root + Path.DirectorySeparatorChar] = new { } }
            }));
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNuGetAsync(assets));
            StringAssert.Contains(error.Message, "Unsafe NuGet package identity");
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmScanRejectsManifestThatDiffersFromLockfile()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-manifest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"),
                """{"name":"sample","dependencies":{"unreviewed":"1.0.0"}}""");
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"),
                """{"lockfileVersion":3,"packages":{"":{}}}""");
            using var client = new HttpClient(new FixedHandler([]));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmScanUsesShrinkwrapInsteadOfStalePackageLock()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-shrinkwrap-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"),
                """{"name":"sample","dependencies":{}}""");
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"),
                """{"lockfileVersion":3,"packages":{"":{"dependencies":{"stale":"1.0.0"}}}}""");
            await File.WriteAllTextAsync(Path.Combine(root, "npm-shrinkwrap.json"),
                """{"lockfileVersion":3,"packages":{"":{}}}""");
            using var client = new HttpClient(new FixedHandler([]));
            var report = await DependencyScanner.ScanDetailedAsync(root, client);
            Assert.AreEqual(0, report.Dependencies.Count);
            Assert.AreEqual(1, report.ScannedProjectCount);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmScanRejectsInstalledPackageMissingFromLockfile()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-extra-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "unreviewed"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"), """{"name":"sample"}""");
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"),
                """{"lockfileVersion":3,"packages":{"":{}}}""");
            await File.WriteAllTextAsync(Path.Combine(root, "node_modules", "unreviewed", "package.json"),
                """{"name":"unreviewed","version":"1.0.0"}""");
            using var client = new HttpClient(new FixedHandler([]));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task NpmRequiredPackageCannotBeHiddenByOptionalLockfileFlag(bool transitive)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-false-optional-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var packages = new Dictionary<string, object>
            {
                [""] = new { dependencies = new Dictionary<string, string>
                    { [transitive ? "parent" : "hidden"] = "1.0.0" } },
                ["node_modules/hidden"] = new
                {
                    version = "1.0.0", optional = true,
                    resolved = "https://registry.example/hidden-1.0.0.tgz", integrity = "sha512-AA=="
                }
            };
            if (transitive)
            {
                packages["node_modules/parent"] = new
                {
                    version = "1.0.0", dependencies = new { hidden = "1.0.0" },
                    resolved = "https://registry.example/parent-1.0.0.tgz", integrity = "sha512-AA=="
                };
                Directory.CreateDirectory(Path.Combine(root, "node_modules", "parent"));
            }
            var lockFile = Path.Combine(root, "package-lock.json");
            await File.WriteAllTextAsync(lockFile, JsonSerializer.Serialize(new { lockfileVersion = 3, packages }));
            var handler = new FixedHandler([]);
            using var client = new HttpClient(handler);
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNpmAsync(lockFile, root, client));
            StringAssert.Contains(error.Message, "Required npm dependency is not installed: node_modules/hidden");
            Assert.AreEqual(0, handler.Calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmAbsentTrulyOptionalPackageIsReportedButNotRejected()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-optional-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            await File.WriteAllTextAsync(lockFile, """
                {"lockfileVersion":3,"packages":{
                  "":{"optionalDependencies":{"platform-only":"1.0.0"}},
                  "node_modules/platform-only":{"version":"1.0.0","optional":true,
                    "resolved":"https://registry.example/platform-only-1.0.0.tgz","integrity":"sha512-AA=="}}}
                """);
            var skipped = new List<string>();
            var handler = new FixedHandler([]);
            using var client = new HttpClient(handler);
            var dependencies = await DependencyScanner.ReadNpmAsync(lockFile, root, client,
                skippedOptional: skipped);
            Assert.AreEqual(0, dependencies.Count);
            Assert.HasCount(1, skipped);
            Assert.AreEqual(0, handler.Calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmScanRejectsNestedInstalledPackageMissingFromLockfile()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-nested-extra-" + Guid.NewGuid().ToString("N"));
        var parent = Path.Combine(root, "node_modules", "approved");
        var extra = Path.Combine(parent, "node_modules", "unreviewed");
        Directory.CreateDirectory(extra);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"), """{"name":"sample"}""");
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"),
                """{"lockfileVersion":3,"packages":{"":{},"node_modules/approved":{}}}""");
            await File.WriteAllTextAsync(Path.Combine(parent, "package.json"),
                """{"name":"approved","version":"1.0.0"}""");
            await File.WriteAllTextAsync(Path.Combine(extra, "package.json"),
                """{"name":"unreviewed","version":"1.0.0"}""");
            using var client = new HttpClient(new FixedHandler([]));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ScanDetailedAsync(root, client));
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmScanAcceptsLockedScopedPackageAndIgnoresBinDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-scoped-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "@example", "package"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", ".bin"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "package.json"),
                """{"name":"sample","dependencies":{"@example/package":"1.0.0"}}""");
            await File.WriteAllTextAsync(Path.Combine(root, "node_modules", "@example", "package", "package.json"),
                """{"name":"@example/package","version":"1.0.0"}""");
            var bytes = CreateNpmArchive("@example/package", "1.0.0");
            var integrity = "sha512-" + Convert.ToBase64String(SHA512.HashData(bytes));
            var lockJson = new
            {
                lockfileVersion = 3,
                packages = new Dictionary<string, object>
                {
                    [""] = new { dependencies = new Dictionary<string, string> { ["@example/package"] = "1.0.0" } },
                    ["node_modules/@example/package"] = new
                    {
                        version = "1.0.0", resolved = "https://registry.example.com/@example/package/-/package-1.0.0.tgz",
                        integrity
                    }
                }
            };
            await File.WriteAllTextAsync(Path.Combine(root, "package-lock.json"), JsonSerializer.Serialize(lockJson));
            using var client = new HttpClient(new FixedHandler(bytes));
            var report = await DependencyScanner.ScanDetailedAsync(root, client);
            Assert.AreEqual(1, report.Dependencies.Count);
            Assert.AreEqual("@example/package", report.Dependencies[0].Name);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NuGetArchiveHashAndSourceAreVerified()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-scanner-" + Guid.NewGuid().ToString("N"));
        var package = Path.Combine(root, "cache", "example", "1.2.3");
        Directory.CreateDirectory(package);
        try
        {
            var bytes = CreateNuGetArchive("Example", "1.2.3");
            await File.WriteAllBytesAsync(Path.Combine(package, "example.1.2.3.nupkg"), bytes);
            await File.WriteAllTextAsync(Path.Combine(package, "example.1.2.3.nupkg.sha512"), Convert.ToBase64String(SHA512.HashData(bytes)));
            // NuGet records a content hash without signature metadata separately
            // from the raw archive hash in .nupkg.sha512.
            var expected512 = Convert.ToBase64String(SHA512.HashData("unsigned package content"u8.ToArray()));
            await File.WriteAllTextAsync(Path.Combine(package, ".nupkg.metadata"), JsonSerializer.Serialize(new
            {
                source = "https://api.nuget.org/v3/index.json", contentHash = expected512
            }));
            var assets = Path.Combine(root, "project.assets.json");
            var assetsJson = new Dictionary<string, object>
            {
                ["targets"] = new Dictionary<string, object> { ["net10.0"] = new Dictionary<string, object>
                    { ["Example/1.2.3"] = new { type = "package" } } },
                ["packageFolders"] = new Dictionary<string, object> { [Path.Combine(root, "cache") + Path.DirectorySeparatorChar] = new { } },
                ["libraries"] = new Dictionary<string, object> { ["Example/1.2.3"] = new { sha512 = expected512 } }
            };
            await File.WriteAllTextAsync(assets, JsonSerializer.Serialize(assetsJson));
            var result = await DependencyScanner.ReadNuGetAsync(assets);
            Assert.AreEqual(1, result.Count);
            Assert.AreEqual(Convert.ToHexStringLower(SHA256.HashData(bytes)), result[0].Sha256);
            Assert.AreEqual("https://api.nuget.org/v3/index.json", result[0].Source);
            await File.WriteAllTextAsync(Path.Combine(package, ".nupkg.metadata"), JsonSerializer.Serialize(new
            {
                source = "https://api.nuget.org/v3/index.json", contentHash = "unexpected-content-hash"
            }));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => DependencyScanner.ReadNuGetAsync(assets));
            await File.WriteAllTextAsync(Path.Combine(package, ".nupkg.metadata"), JsonSerializer.Serialize(new
            {
                source = "https://api.nuget.org/v3/index.json", contentHash = expected512
            }));
            var wrongIdentity = CreateNuGetArchive("Different", "1.2.3");
            await File.WriteAllBytesAsync(Path.Combine(package, "example.1.2.3.nupkg"), wrongIdentity);
            await File.WriteAllTextAsync(Path.Combine(package, "example.1.2.3.nupkg.sha512"),
                Convert.ToBase64String(SHA512.HashData(wrongIdentity)));
            var identityError = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNuGetAsync(assets));
            StringAssert.Contains(identityError.Message, "archive identity differs");
            var wrongVersion = CreateNuGetArchive("Example", "2.0.0");
            await File.WriteAllBytesAsync(Path.Combine(package, "example.1.2.3.nupkg"), wrongVersion);
            await File.WriteAllTextAsync(Path.Combine(package, "example.1.2.3.nupkg.sha512"),
                Convert.ToBase64String(SHA512.HashData(wrongVersion)));
            var versionError = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNuGetAsync(assets));
            StringAssert.Contains(versionError.Message, "archive identity differs");
            await File.WriteAllBytesAsync(Path.Combine(package, "example.1.2.3.nupkg"), "tampered"u8.ToArray());
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => DependencyScanner.ReadNuGetAsync(assets));
        }
        finally { Directory.Delete(root, true); }
    }

    private static byte[] CreateNuGetArchive(string name, string version)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        using (var manifest = new StreamWriter(zip.CreateEntry($"{name}.nuspec").Open(), Encoding.UTF8))
            manifest.Write($"<package><metadata><id>{name}</id><version>{version}</version></metadata></package>");
        return output.ToArray();
    }

    [TestMethod]
    public async Task NpmLockIntegrityIsVerified()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "node_modules", "sample"));
        try
        {
            await File.WriteAllTextAsync(Path.Combine(root, "node_modules", "sample", "package.json"),
                """{"name":"sample","version":"1.0.0"}""");
            var bytes = CreateNpmArchive("sample", "1.0.0");
            var integrity = Convert.ToBase64String(SHA512.HashData(bytes));
            var lockFile = Path.Combine(root, "package-lock.json");
            var lockJson = new
            {
                lockfileVersion = 3,
                packages = new Dictionary<string, object>
                {
                    [""] = new { },
                    ["node_modules/sample"] = new { version = "1.0.0", resolved = "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz", integrity = "sha512-" + integrity }
                }
            };
            await File.WriteAllTextAsync(lockFile, JsonSerializer.Serialize(lockJson));
            using var client = new HttpClient(new FixedHandler(bytes));
            var result = await DependencyScanner.ReadNpmAsync(lockFile, root, client);
            Assert.AreEqual(1, result.Count);
            Assert.AreEqual(Convert.ToHexStringLower(SHA256.HashData(bytes)), result[0].Sha256);
            using var changed = new HttpClient(new FixedHandler("changed"u8.ToArray()));
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => DependencyScanner.ReadNpmAsync(lockFile, root, changed));
            using var redirected = new HttpClient(new OtherOriginHandler(bytes));
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNpmAsync(lockFile, root, redirected));
            StringAssert.Contains(error.Message, "different source");

            var wrongIdentity = CreateNpmArchive("different", "1.0.0");
            var wrongLockJson = new
            {
                lockfileVersion = 3,
                packages = new Dictionary<string, object>
                {
                    [""] = new { },
                    ["node_modules/sample"] = new
                    {
                        version = "1.0.0", resolved = "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz",
                        integrity = "sha512-" + Convert.ToBase64String(SHA512.HashData(wrongIdentity))
                    }
                }
            };
            await File.WriteAllTextAsync(lockFile, JsonSerializer.Serialize(wrongLockJson));
            using var wrongClient = new HttpClient(new FixedHandler(wrongIdentity));
            var identityError = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNpmAsync(lockFile, root, wrongClient));
            StringAssert.Contains(identityError.Message, "archive identity differs");
        }
        finally { Directory.Delete(root, true); }
    }

    private static byte[] CreateNpmArchive(string name, string version)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gzip, leaveOpen: true))
        {
            var manifest = JsonSerializer.Serialize(new { name, version });
            var entry = new PaxTarEntry(TarEntryType.RegularFile, "package/package.json")
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes(manifest))
            };
            tar.WriteEntry(entry);
        }
        return output.ToArray();
    }

    [TestMethod]
    public async Task NpmArchiveOutsideSelectedRegistryIsRejectedBeforeDownload()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-source-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            await File.WriteAllTextAsync(lockFile, """
                {"lockfileVersion":3,"packages":{"":{},"node_modules/sample":{
                  "version":"1.0.0","resolved":"https://foreign.example/sample-1.0.0.tgz",
                  "integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}}
                """);
            var handler = new FixedHandler([]);
            using var client = new HttpClient(handler);
            var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNpmAsync(lockFile, root, client,
                    expectedSource: "https://npm.aiursoft.com"));
            StringAssert.Contains(error.Message, "outside the selected registry");
            Assert.AreEqual(0, handler.Calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    [DataRow("node_modules/../outside")]
    [DataRow("node_modules/sample/../../outside")]
    [DataRow("node_modules\\outside")]
    [DataRow("node_modules//outside")]
    [DataRow("workspace/node_modules/outside")]
    public async Task NpmLockPackagePathsCannotEscapeInstalledPackageTree(string packagePath)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            await File.WriteAllTextAsync(lockFile, JsonSerializer.Serialize(new
            {
                lockfileVersion = 3,
                packages = new Dictionary<string, object>
                {
                    [""] = new { },
                    [packagePath] = new
                    {
                        version = "1.0.0", resolved = "https://registry.example.com/sample.tgz",
                        integrity = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
                    }
                }
            }));
            var handler = new FixedHandler([]);
            using var client = new HttpClient(handler);
            var sourceError = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ValidateNpmArchiveSourcesAsync(lockFile, "https://registry.example.com"));
            StringAssert.Contains(sourceError.Message, "package path");
            var scanError = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                DependencyScanner.ReadNpmAsync(lockFile, root, client));
            StringAssert.Contains(scanError.Message, "package path");
            Assert.AreEqual(0, handler.Calls);
        }
        finally { Directory.Delete(root, true); }
    }

    [TestMethod]
    public async Task NpmArchiveSourceCheckAllowsNestedPackagePath()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-npm-nested-path-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var lockFile = Path.Combine(root, "package-lock.json");
            await File.WriteAllTextAsync(lockFile, """
                {"lockfileVersion":3,"packages":{"":{},"node_modules/parent/node_modules/@example/child":{
                  "version":"1.0.0","resolved":"https://registry.example.com/child.tgz"}}}
                """);
            await DependencyScanner.ValidateNpmArchiveSourcesAsync(lockFile, "https://registry.example.com");
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class FixedHandler(byte[] bytes) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(bytes)
            });
        }
    }

    private sealed class OtherOriginHandler(byte[] bytes) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://other-registry.example/sample-1.0.0.tgz"),
                Content = new ByteArrayContent(bytes)
            });
    }
}
