using System.Net;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Configuration;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Services.Resolution;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class SupplyChainPagesTests : TestBase
{
#if DEBUG
    private const string BuildConfiguration = "Debug";
#else
    private const string BuildConfiguration = "Release";
#endif

    [TestInitialize]
    public void AllowFixtureRegistries()
    {
        var configuration = GetService<IConfiguration>();
        configuration["SupplyChain:NuGetSources:1"] = "https://api.nuget.org/v3/index.json";
        configuration["SupplyChain:NpmSources:1"] = "https://registry.npmjs.org";
    }

    private async Task AddCheckKeyAsync(string secret, bool baseline = false)
    {
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var user = await db.Users.SingleAsync(u => u.Email == "admin@default.com");
        var hash = Services.Authentication.ApiKeyPermissions.Hash(secret);
        var key = await db.ApiKeys.SingleOrDefaultAsync(k => k.SecretHash == hash);
        if (key == null)
        {
            key = new ApiKey { Name = secret, UserId = user.Id, SecretHash = hash };
            db.ApiKeys.Add(key);
        }
        key.CanPublishBaselines = baseline;
        key.IsEnabled = true;
        key.ExpirationTime = DateTime.UtcNow.AddYears(1);
        await db.SaveChangesAsync();
    }

    [TestMethod]
    public async Task PersonalKeysRotateWithoutDowntimeAndRespectOwnershipAndRevocation()
    {
        await LoginAsAdmin();
        async Task<string> CreateKey(string name, bool baseline)
        {
            using var response = await PostForm("/ApiKeys/Create", new Dictionary<string, string>
            {
                ["Name"] = name,
                ["IsEnabled"] = "true",
                ["CanPublishBaselines"] = baseline.ToString(),
                ["ExpirationTime"] = DateTime.UtcNow.AddDays(30).ToString("s")
            });
            Assert.AreEqual(HttpStatusCode.Found, response.StatusCode);
            var page = await Http.GetStringAsync("/ApiKeys");
            var match = System.Text.RegularExpressions.Regex.Match(page, "value=\"([A-F0-9]{64})\"");
            Assert.IsTrue(match.Success);
            var secret = match.Groups[1].Value;
            Assert.DoesNotContain(secret, await Http.GetStringAsync("/ApiKeys"));
            return secret;
        }
        var oldKey = await CreateKey("CI old", true);
        var newKey = await CreateKey("CI new", true);
        Guid oldId;
        string ownerId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var old = await db.ApiKeys.SingleAsync(k => k.Name == "CI old");
            oldId = old.Id; ownerId = old.UserId;
            Assert.AreNotEqual(oldKey, old.SecretHash);
            Assert.AreEqual(64, old.SecretHash.Length);
        }
        async Task<HttpStatusCode> Check(string secret)
        {
            Http.DefaultRequestHeaders.Remove("X-S360-Key");
            Http.DefaultRequestHeaders.Add("X-S360-Key", secret);
            using var r = await Http.PostAsJsonAsync("/api/check", new CheckRequest
            {
                Project = "rotation-test",
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                Context = new CheckContext { Purpose = "baseline", UserId = "forged", ApiKeyId = "forged" }
            });
            return r.StatusCode;
        }
        Assert.AreEqual(HttpStatusCode.OK, await Check(oldKey));
        Assert.AreEqual(HttpStatusCode.OK, await Check(newKey));
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var report = await db.BuildChecks.FirstAsync(c => c.Project == "rotation-test");
            var context = BuildCheckRun.ReadContext(report.ContextJson)!;
            Assert.AreEqual(ownerId, context.UserId);
            Assert.AreNotEqual("forged", context.ApiKeyId);
        }
        using (var deleted = await PostForm("/ApiKeys/Delete", new Dictionary<string, string>
        { ["id"] = oldId.ToString() }, tokenUrl: "/ApiKeys"))
            Assert.AreEqual(HttpStatusCode.Found, deleted.StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, await Check(oldKey));
        Assert.AreEqual(HttpStatusCode.OK, await Check(newKey));
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Id == ownerId);
            user.LockoutEnabled = true; user.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
            await db.SaveChangesAsync();
        }
        var lockedStatus = await Check(newKey);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Id == ownerId);
            user.LockoutEnd = null;
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(HttpStatusCode.Unauthorized, lockedStatus);
    }

    [TestMethod]
    public async Task PersonalKeyExpiryDisableAndBaselinePermissionAreEnforced()
    {
        await AddCheckKeyAsync("scoped-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "scoped-key");
        async Task<HttpStatusCode> Check(string purpose = "review")
        {
            using var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
            {
                Project = "scope-test",
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                Context = new CheckContext { Purpose = purpose }
            });
            return response.StatusCode;
        }
        Assert.AreEqual(HttpStatusCode.OK, await Check("baseline"));
        List<Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>> grants;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            grants = await db.RoleClaims.Where(c => c.ClaimValue == Authorization.AppPermissionNames.CanPublishBaselines).ToListAsync();
            db.RoleClaims.RemoveRange(grants);
            await db.SaveChangesAsync();
        }
        HttpStatusCode revokedStatus;
        try { revokedStatus = await Check("baseline"); }
        finally
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.RoleClaims.AddRange(grants);
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(HttpStatusCode.Forbidden, revokedStatus);
        Assert.AreEqual(HttpStatusCode.OK, await Check());
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            (await db.ApiKeys.SingleAsync(k => k.Name == "scoped-key")).ExpirationTime = DateTime.UtcNow.AddMinutes(-1);
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(HttpStatusCode.Unauthorized, await Check());
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var key = await db.ApiKeys.SingleAsync(k => k.Name == "scoped-key");
            key.ExpirationTime = DateTime.UtcNow.AddDays(1); key.IsEnabled = false;
            await db.SaveChangesAsync();
        }
        Assert.AreEqual(HttpStatusCode.Unauthorized, await Check());
        GetService<IConfiguration>()["SupplyChain:CheckApiKey"] = "legacy-static-key";
        GetService<IConfiguration>()["SupplyChain:BaselineApiKey"] = "legacy-static-key";
        Http.DefaultRequestHeaders.Remove("X-S360-Key");
        Http.DefaultRequestHeaders.Add("X-S360-Key", "legacy-static-key");
        Assert.AreEqual(HttpStatusCode.Unauthorized, await Check());
    }

    [TestMethod]
    public async Task PersonalKeysRejectOtherUsersAndRequireCurrentGrants()
    {
        await LoginAsAdmin();
        await AddCheckKeyAsync("other-owner-key", baseline: true);
        Guid foreignId;
        using (var scope = Server!.Services.CreateScope())
            foreignId = (await scope.ServiceProvider.GetRequiredService<TemplateDbContext>().ApiKeys.SingleAsync(k => k.Name == "other-owner-key")).Id;
        await PostForm("/Account/LogOff", new Dictionary<string, string>(), tokenUrl: "/ApiKeys");
        var account = await RegisterAndLoginAsync();
        using (var denied = await Http.GetAsync("/ApiKeys"))
            AssertRedirect(denied, "/Error/Code403", exact: false);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Email == account.email);
            db.UserClaims.Add(new Microsoft.AspNetCore.Identity.IdentityUserClaim<string>
            {
                UserId = user.Id,
                ClaimType = Authorization.AppPermissions.Type,
                ClaimValue = Authorization.AppPermissionNames.CanManageApiKeys
            });
            await db.SaveChangesAsync();
        }
        // Refresh the cookie for the newly granted navigation permission.
        await Http.GetAsync("/Account/LogOff");
        await PostForm("/Account/Login", new Dictionary<string, string>
        { ["EmailOrUserName"] = account.email, ["Password"] = account.password });
        Assert.DoesNotContain("other-owner-key", await Http.GetStringAsync("/ApiKeys"));
        using (var edit = await Http.GetAsync("/ApiKeys/Edit/" + foreignId)) Assert.AreEqual(HttpStatusCode.NotFound, edit.StatusCode);
        using (var delete = await PostForm("/ApiKeys/Delete", new Dictionary<string, string>
        { ["id"] = foreignId.ToString() }, tokenUrl: "/ApiKeys/Create"))
            Assert.AreEqual(HttpStatusCode.NotFound, delete.StatusCode);
        using (var escalate = await PostForm("/ApiKeys/Create", new Dictionary<string, string>
        { ["Name"] = "escalation", ["CanPublishBaselines"] = "true", ["ExpirationTime"] = DateTime.UtcNow.AddDays(1).ToString("s") }))
            AssertRedirect(escalate, "/Error/Code403", exact: false);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Email == account.email);
            db.ApiKeys.Add(new ApiKey { UserId = user.Id, Name = "personal", SecretHash = Services.Authentication.ApiKeyPermissions.Hash("personal") });
            await db.SaveChangesAsync();
        }
        Http.DefaultRequestHeaders.Add("X-S360-Key", "personal");
        var request = new CheckRequest { RunId = Guid.NewGuid().ToString("N"), ScannedProjectCount = 1 };
        using (var accepted = await Http.PostAsJsonAsync("/api/check", request)) Assert.AreEqual(HttpStatusCode.OK, accepted.StatusCode);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Email == account.email);
            db.UserClaims.RemoveRange(db.UserClaims.Where(c => c.UserId == user.Id));
            await db.SaveChangesAsync();
        }
        request.RunId = Guid.NewGuid().ToString("N");
        using (var revoked = await Http.PostAsJsonAsync("/api/check", request)) Assert.AreEqual(HttpStatusCode.Unauthorized, revoked.StatusCode);
        using (var staleCookie = await Http.GetAsync("/ApiKeys"))
            AssertRedirect(staleCookie, "/Error/Code403", exact: false);
    }

    [TestMethod]
    public async Task QueuedRequestIsRejectedBeforeResolutionWhenSourceOrDirectPackageIsBlocked()
    {
        int removedSourceId;
        int blockedPackageId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var userId = db.Users.Single(u => u.Email == "admin@default.com").Id;
            var removedSource = new DependencyApplication
            {
                RequestedByUserId = userId,
                Ecosystem = "npm",
                Source = "https://127.0.0.1",
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage("is-number", "1.0.0") }),
                Justification = "Check queued source policy",
                ResolutionContext = "npm; pending",
                Status = ApplicationStatus.Resolving
            };
            var blockedPackage = new DependencyApplication
            {
                RequestedByUserId = userId,
                Ecosystem = "npm",
                Source = "https://registry.npmjs.org",
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage("blocked-before-download", "1.0.0") }),
                Justification = "Check queued block policy",
                ResolutionContext = "npm; pending",
                Status = ApplicationStatus.Resolving
            };
            db.DependencyApplications.AddRange(removedSource, blockedPackage);
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Ecosystem = "npm",
                PackagePattern = "blocked-before-download",
                Version = "*",
                Justification = "Newly blocked while queued",
                Status = RuleStatus.Approved
            });
            await db.SaveChangesAsync();
            removedSourceId = removedSource.Id;
            blockedPackageId = blockedPackage.Id;
        }

        using (var scope = Server!.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<DependencyResolutionJob>().ExecuteAsync();

        using var verifyScope = Server!.Services.CreateScope();
        var verify = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var removed = await verify.DependencyApplications.SingleAsync(a => a.Id == removedSourceId);
        var blocked = await verify.DependencyApplications.SingleAsync(a => a.Id == blockedPackageId);
        Assert.AreEqual(ApplicationStatus.Failed, removed.Status);
        StringAssert.Contains(removed.Failure!, "no longer permitted");
        Assert.AreEqual(ApplicationStatus.Failed, blocked.Status);
        StringAssert.Contains(blocked.Failure!, "Newly blocked while queued");
        Assert.AreEqual(0, await verify.PackageVersions.CountAsync());
    }

    [TestMethod]
    [DataRow(null, false)]
    [DataRow("baseline", false)]
    [DataRow(null, true)]
    public async Task DependencyFreeProjectPassesCliAndOnlyBaselineRecordsCompleteRun(string? purpose, bool anonymous)
    {
        if (anonymous)
        {
            using var scope = Server!.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<GlobalSettingsService>()
                .UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "True");
        }
        var checkKey = purpose == "baseline" ? "integration-cli-baseline-key" : "integration-cli-check-key";
        await AddCheckKeyAsync("integration-cli-baseline-key", baseline: true);
        await AddCheckKeyAsync("integration-cli-check-key");
        var reportedProject = "integration/dependency-free-" + Guid.NewGuid().ToString("N");
        var root = Path.Combine(Path.GetTempPath(), "s360-cli-pass-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var project = Path.Combine(root, "Empty.csproj");
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>");
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { },
                    libraries = new { },
                    project = new { restore = new { projectPath = project } }
                }));
            var solution = await DependencyScannerTests.WriteSolutionAsync(root, project);
            var clientProject = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                "../../../../src/Aiursoft.S360.Client/Aiursoft.S360.Client.csproj"));
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = root
            };
            foreach (var argument in new[]
                     {
                         "run", "--no-build", "--no-restore", "--configuration", BuildConfiguration,
                         "--project", clientProject, "--",
                         "check", "--path", solution, "--server", $"http://localhost:{Port}", "--ecosystem", "nuget"
                     }) start.ArgumentList.Add(argument);
            if (anonymous) start.Environment.Remove("S360_CHECK_KEY");
            else start.Environment["S360_CHECK_KEY"] = checkKey;
            if (purpose != null)
            {
                start.ArgumentList.Add("--purpose");
                start.ArgumentList.Add(purpose);
            }
            start.Environment["CI_PROJECT_PATH"] = reportedProject;
            start.Environment["CI_PROJECT_DIR"] = root;
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the CLI.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("The S360 CLI did not complete its dependency-free check.");
            }
            var output = await outputTask + await errorTask;
            Assert.AreEqual(0, process.ExitCode, output);
            StringAssert.Contains(output, "S360 approved 0 dependency artifacts across 1 supported projects.");
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var checks = await db.BuildChecks.Include(c => c.Dependencies)
                .Where(c => c.Project == reportedProject + "//" + Path.GetFileName(solution)).ToListAsync();
            if (purpose == "baseline")
            {
                Assert.HasCount(1, checks);
                Assert.AreEqual("baseline", BuildCheckRun.Purpose(checks[0].ContextJson));
                Assert.AreEqual(Path.GetFileName(solution), BuildCheckRun.ReadContext(checks[0].ContextJson)!.SolutionPath);
                Assert.IsNotNull(DependencyReportGraph.Read(checks[0].GraphJson!).Solution);
                Assert.AreEqual("nuget", BuildCheckRun.ReadContext(checks[0].ContextJson)!.Ecosystem);
                Assert.AreEqual(1, checks[0].ScannedProjectCount);
                Assert.HasCount(0, checks[0].Dependencies);
                Assert.IsTrue(BuildCheckRun.IsComplete(checks));
            }
            else Assert.HasCount(0, checks);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            using var scope = Server!.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<GlobalSettingsService>()
                .UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "False");
        }
    }

    [TestMethod]
    [DataRow("review")]
    [DataRow("baseline")]
    public async Task CliRejectsPackageFromUnconfiguredSourceWithActionableDetails(string purpose)
    {
        const string checkKey = "integration-cli-source-key";
        const string source = "https://unconfigured.example.test/v3/index.json";
        await AddCheckKeyAsync(checkKey, baseline: purpose == "baseline");
        var root = Path.Combine(Path.GetTempPath(), "s360-cli-source-" + Guid.NewGuid().ToString("N"));
        var packageName = "example." + Guid.NewGuid().ToString("N");
        const string version = "1.2.3";
        var packageDirectory = Path.Combine(root, "cache", packageName, version);
        Directory.CreateDirectory(packageDirectory);
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var project = Path.Combine(root, "Sample.csproj");
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>");
            using var archive = new MemoryStream();
            using (var zip = new ZipArchive(archive, ZipArchiveMode.Create, leaveOpen: true))
            using (var manifest = new StreamWriter(zip.CreateEntry(packageName + ".nuspec").Open(), Encoding.UTF8))
                await manifest.WriteAsync($"<package><metadata><id>{packageName}</id><version>{version}</version></metadata></package>");
            var bytes = archive.ToArray();
            var sha512 = Convert.ToBase64String(SHA512.HashData(bytes));
            await File.WriteAllBytesAsync(Path.Combine(packageDirectory, $"{packageName}.{version}.nupkg"), bytes);
            await File.WriteAllTextAsync(Path.Combine(packageDirectory, $"{packageName}.{version}.nupkg.sha512"), sha512);
            await File.WriteAllTextAsync(Path.Combine(packageDirectory, ".nupkg.metadata"),
                JsonSerializer.Serialize(new { source, contentHash = sha512 }));
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object>
                    {
                        ["net10.0"] = new Dictionary<string, object>
                        {
                            [$"{packageName}/{version}"] = new { type = "package" }
                        }
                    },
                    packageFolders = new Dictionary<string, object>
                    {
                        [Path.Combine(root, "cache") + Path.DirectorySeparatorChar] = new { }
                    },
                    libraries = new Dictionary<string, object>
                    {
                        [$"{packageName}/{version}"] = new { sha512 }
                    },
                    project = new
                    {
                        restore = new { projectPath = project },
                        frameworks = new Dictionary<string, object>
                        { ["net10.0"] = new { dependencies = new Dictionary<string, object> { [packageName] = new { target = "Package", version } } } }
                    }
                }));
            var solution = await DependencyScannerTests.WriteSolutionAsync(root, project);
            var clientProject = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                "../../../../src/Aiursoft.S360.Client/Aiursoft.S360.Client.csproj"));
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                WorkingDirectory = root
            };
            foreach (var argument in new[]
                     {
                         "run", "--no-build", "--no-restore", "--configuration", BuildConfiguration,
                         "--project", clientProject, "--", "check", "--path", solution,
                         "--server", $"http://localhost:{Port}", "--purpose", purpose
                     }) start.ArgumentList.Add(argument);
            start.Environment["S360_CHECK_KEY"] = checkKey;
            start.Environment["CI_PROJECT_PATH"] = "integration/unconfigured-source";
            start.Environment["CI_PROJECT_DIR"] = root;
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the CLI.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("The S360 CLI did not finish its denied-source check.");
            }
            var output = await outputTask + await errorTask;
            Assert.AreNotEqual(0, process.ExitCode);
            StringAssert.Contains(output, packageName + "@" + version);
            StringAssert.Contains(output, source);
            StringAssert.Contains(output, "Package source is not permitted");
            StringAssert.Contains(output, $"S360 BLOCKED ({purpose}): 1 package artifact(s)");
            StringAssert.Contains(output, "Project: Sample.csproj");
            StringAssert.Contains(output, "policy rejection");
            Assert.DoesNotContain("Unhandled exception", output);
            Assert.DoesNotContain("InvalidOperationException", output);
            Assert.DoesNotContain("S360 approved", output);
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.AreEqual(purpose == "baseline", await db.BuildChecks.AnyAsync(c => c.Project == "integration/unconfigured-source//" + Path.GetFileName(solution)));
            Assert.AreEqual(purpose == "baseline", await db.BuildCheckDependencies.AnyAsync(d => d.Name == packageName));
            if (purpose == "baseline")
            {
                var report = await db.BuildChecks.SingleAsync(c => c.Project == "integration/unconfigured-source//" + Path.GetFileName(solution));
                Assert.IsFalse(report.Trusted);
                Assert.AreEqual("baseline", BuildCheckRun.Purpose(report.ContextJson));
            }
            Assert.IsFalse(await db.PackageVersions.AnyAsync(a => a.Name == packageName));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [TestMethod]
    public async Task AdministratorCanOpenSupplyChainPages()
    {
        await LoginAsAdmin();
        foreach (var (path, guideTitle) in new[]
                 {
                     ("/SupplyChain/Index?tab=rules&ecosystem=nuget", "Exact versus wildcard"),
                     ("/SupplyChain/Blocklist?ecosystem=nuget", "How absolute blocking works"),
                     ("/DependencyRequests/Index", "Package source"),
                     ("/DependencyReviews/Index", "Dependency approvals"),
                     ("/VulnerabilityAudit/Index?ecosystem=nuget", "Quick versus detailed audit"),
                     ("/BuildChecks/Index", "Accepted versus enforced")
                 })
        {
            using var response = await Http.GetAsync(path);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, path);
            var html = await response.Content.ReadAsStringAsync();
            if (path != "/DependencyReviews/Index")
                StringAssert.Contains(html, "s360-concept-rail", path);
            StringAssert.Contains(html, guideTitle, path);
            if (path.StartsWith("/SupplyChain/Index?tab=rules", StringComparison.Ordinal))
            {
                StringAssert.Contains(html, "s360-workspace-jumps");
                StringAssert.Contains(html, "Manage blocklist");
            }
            if (path == "/DependencyRequests/Index")
            {
                StringAssert.Contains(html, "data-ecosystem=\"nuget\"");
                StringAssert.Contains(html, "data-ecosystem=\"npm\"");
                StringAssert.Contains(html, "ecosystem.addEventListener('change', syncSource)");
            }
        }

        int requestId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var request = new DependencyApplication
            {
                RequestedByUserId = db.Users.Single(u => u.Email == "admin@default.com").Id,
                Ecosystem = "nuget",
                Source = "https://api.nuget.org/v3/index.json",
                Justification = "Read the concept guide",
                Status = ApplicationStatus.Failed,
                Failure = "Fixture",
                ResolutionContext = "net10.0"
            };
            db.DependencyApplications.Add(request);
            await db.SaveChangesAsync();
            requestId = request.Id;
        }
        using var details = await Http.GetAsync($"/DependencyRequests/Details/{requestId}");
        Assert.AreEqual(HttpStatusCode.OK, details.StatusCode);
        var detailsHtml = await details.Content.ReadAsStringAsync();
        StringAssert.Contains(detailsHtml, "Reading this report");
        Assert.DoesNotContain("Artifact SHA-256", detailsHtml);
        StringAssert.Contains(detailsHtml, "Approved versus checked");
    }

    [TestMethod]
    public async Task RequestDetailsSeparatesApprovalFromPendingVulnerabilityAudit()
    {
        await LoginAsAdmin();
        var name = "Example.AuditPending." + Guid.NewGuid().ToString("N");
        int requestId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var source = "https://api.nuget.org/v3/index.json";
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source
            };
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            var application = new DependencyApplication
            {
                RequestedByUserId = db.Users.Single(u => u.Email == "admin@default.com").Id,
                Ecosystem = "nuget",
                Source = source,
                ResolutionContext = "net10.0",
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage(name, "1.0.0") }),
                Justification = "Review while audit is pending",
                Status = ApplicationStatus.ReadyForReview,
                Packages = [new ApplicationPackage { ApplicationId = 0, PackageVersionId = artifact.Id, PackageVersion = artifact, IsDirect = true }]
            };
            db.DependencyApplications.Add(application);
            await db.SaveChangesAsync();
            application.ReportHash = ReportFingerprint.ComputePersisted(application);
            await db.SaveChangesAsync();
            requestId = application.Id;
        }

        using var page = await Http.GetAsync($"/DependencyRequests/Details/{requestId}");
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Already authorized: 1");
        StringAssert.Contains(html, "New review items: 0");
        StringAssert.Contains(html, "Authorized but not check-ready: 1");
        StringAssert.Contains(html, "Current check blocked");
        StringAssert.Contains(html, "Current vulnerability data is unavailable");

        var configuration = GetService<IConfiguration>();
        var originalSource = configuration["SupplyChain:NuGetSources:1"];
        configuration["SupplyChain:NuGetSources:1"] = "https://replacement.example.com/v3/index.json";
        try
        {
            using var removed = await Http.GetAsync($"/DependencyRequests/Details/{requestId}");
            removed.EnsureSuccessStatusCode();
            var removedHtml = await removed.Content.ReadAsStringAsync();
            StringAssert.Contains(removedHtml, "Already authorized: 0");
            StringAssert.Contains(removedHtml, "New review items: 0");
            StringAssert.Contains(removedHtml, "Source not permitted: 1");
            StringAssert.Contains(removedHtml, "Package source is no longer permitted for S360 checks");
            using var requests = await Http.GetAsync("/DependencyRequests/Index");
            requests.EnsureSuccessStatusCode();
            StringAssert.Contains(await requests.Content.ReadAsStringAsync(),
                "Package source is no longer permitted for S360 checks");
        }
        finally { configuration["SupplyChain:NuGetSources:1"] = originalSource; }
    }

    [TestMethod]
    public async Task FailedRequestOffersOwnerANewSubmissionWithoutChangingHistory()
    {
        await LoginAsAdmin();
        int ownId;
        int otherId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var own = new DependencyApplication
            {
                RequestedByUserId = db.Users.Single(u => u.Email == "admin@default.com").Id,
                Ecosystem = "nuget",
                Source = "https://nuget.aiursoft.com/v3/index.json",
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage("Example.Retry", "1.0.0") }),
                Justification = "Retry transient registry failure",
                Project = "docs-viewer",
                ResolutionContext = "net10.0; pending",
                Status = ApplicationStatus.Failed,
                Failure = "Registry temporarily unavailable"
            };
            var other = new DependencyApplication
            {
                RequestedByUserId = "another-employee",
                Ecosystem = own.Ecosystem,
                Source = own.Source,
                DirectPackages = own.DirectPackages,
                Justification = own.Justification,
                ResolutionContext = own.ResolutionContext,
                Status = ApplicationStatus.Failed,
                Failure = own.Failure
            };
            db.DependencyApplications.AddRange(own, other);
            await db.SaveChangesAsync();
            ownId = own.Id;
            otherId = other.Id;
        }

        using (var ownPage = await Http.GetAsync($"/DependencyRequests/Details/{ownId}"))
        {
            ownPage.EnsureSuccessStatusCode();
            var html = await ownPage.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "Retry as a new request");
            StringAssert.Contains(html, "Example.Retry@1.0.0");
            StringAssert.Contains(html, "The failed request stays in your history");
        }
        using (var otherPage = await Http.GetAsync($"/DependencyRequests/Details/{otherId}"))
        {
            otherPage.EnsureSuccessStatusCode();
            Assert.DoesNotContain("Retry as a new request", await otherPage.Content.ReadAsStringAsync());
        }
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(ApplicationStatus.Failed,
            (await verifyDb.DependencyApplications.SingleAsync(a => a.Id == ownId)).Status);
    }

    [TestMethod]
    public async Task MyRequestsShowsNewBlockWithoutChangingHistoricalApproval()
    {
        await LoginAsAdmin();
        var name = "Example.LaterBlocked." + Guid.NewGuid().ToString("N");
        var childName = name + ".Child";
        int requestId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var rootArtifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json"
            };
            var childArtifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = childName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json"
            };
            var application = new DependencyApplication
            {
                RequestedByUserId = db.Users.Single(u => u.Email == "admin@default.com").Id,
                Ecosystem = "nuget",
                Source = "https://api.nuget.org/v3/index.json",
                Justification = "Historical approval",
                Project = "later-blocked-project",
                ResolutionContext = "net10.0",
                Status = ApplicationStatus.Approved,
                Packages =
                [
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, IsDirect = true, PackageVersion = rootArtifact },
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, IsDirect = false, PackageVersion = childArtifact }
                ]
            };
            db.DependencyApplications.Add(application);
            await db.SaveChangesAsync();
            requestId = application.Id;
        }
        using (var before = await Http.GetAsync("/DependencyRequests/Index"))
        {
            before.EnsureSuccessStatusCode();
            Assert.DoesNotContain("Currently blocked", await before.Content.ReadAsStringAsync());
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = childName,
                Version = "*",
                Justification = "Incident discovered after approval"
            });
            await db.SaveChangesAsync();
        }
        using var after = await Http.GetAsync("/DependencyRequests/Index");
        after.EnsureSuccessStatusCode();
        var html = await after.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Approved");
        StringAssert.Contains(html, "Currently blocked");
        StringAssert.Contains(html, "Incident discovered after approval");
        StringAssert.Contains(html, "Introduction path: " + childName);
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(ApplicationStatus.Approved,
            (await verifyDb.DependencyApplications.SingleAsync(a => a.Id == requestId)).Status);
    }

    [TestMethod]
    public async Task FailedLatestVulnerabilitySyncIsNotDisplayedAsFresh()
    {
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var state = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (state == null)
            {
                state = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(state);
            }
            state.LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-10);
            state.LastAttemptAtUtc = DateTime.UtcNow;
            state.LastSuccessfulAttemptAtUtc = DateTime.UtcNow;
            state.LastError = "OSV temporarily unavailable";
            await db.SaveChangesAsync();
        }
        using var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "alert-warning");
        StringAssert.Contains(html, "the latest synchronization failed");
        StringAssert.Contains(html, "OSV temporarily unavailable");
    }

    [TestMethod]
    public async Task DetailedAuditShowsAdvisoryRevisionHistory()
    {
        await LoginAsAdmin();
        var sourceId = "GHSA-history-" + Guid.NewGuid().ToString("N");
        var relatedId = "OSV-history-" + Guid.NewGuid().ToString("N");
        var sharedAlias = "CVE-2026-" + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Vulnerabilities.AddRange(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = "Example.History",
                SourceId = sourceId,
                Summary = "Updated advisory",
                RawAffectedJson = "[]",
                Aliases = JsonSerializer.Serialize(new[] { sharedAlias }),
                Revisions =
                [
                    new VulnerabilityRevision { VulnerabilityId = 0, Summary = "Original advisory", RawAffectedJson = "[]" },
                    new VulnerabilityRevision { VulnerabilityId = 0, Summary = "Updated advisory", RawAffectedJson = "[]" }
                ]
            }, new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = "Example.History",
                SourceId = relatedId,
                Summary = "Related source record",
                RawAffectedJson = "[]",
                Aliases = JsonSerializer.Serialize(new[] { sharedAlias })
            });
            await db.SaveChangesAsync();
        }
        using var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, sourceId);
        StringAssert.Contains(html, relatedId);
        StringAssert.Contains(html, "Correlated source records");
        Assert.AreEqual(1, html.Split("<strong>Example.History</strong>").Length - 1);
        StringAssert.Contains(html, "Advisory change history");
        StringAssert.Contains(html, "Original advisory");
        StringAssert.Contains(html, "Updated advisory");
    }

    [TestMethod]
    public async Task CorrelatedAdvisoriesCountOnceButKeepRiskFromEitherSource()
    {
        await LoginAsAdmin();
        var package = "Example.Correlated." + Guid.NewGuid().ToString("N");
        var alias = "CVE-2026-" + Guid.NewGuid().ToString("N");
        var range = $$"""
            [{"package":{"ecosystem":"NuGet","name":"{{package}}"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
            """;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.AddRange([new PackageRule
                {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Ecosystem = "nuget", PackagePattern = package, Version = "10.0.*",
                    Source = "https://api.nuget.org/v3/index.json", Status = RuleStatus.Approved
                }]);
            db.Vulnerabilities.AddRange(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = package,
                SourceId = "GHSA-" + Guid.NewGuid().ToString("N"),
                Aliases = JsonSerializer.Serialize(new[] { alias }),
                RawAffectedJson = "[]"
            }, new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = package,
                SourceId = "OSV-" + Guid.NewGuid().ToString("N"),
                Aliases = JsonSerializer.Serialize(new[] { alias }),
                RawAffectedJson = range
            });
            await db.SaveChangesAsync();
        }
        using var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.AreEqual(1, html.Split($"<strong>{package}</strong>").Length - 1);
        StringAssert.Contains(html, "Correlated source records");
        StringAssert.Contains(html, "Current authorization range permits an affected version");
    }

    [TestMethod]
    public async Task MissingSupplyChainFormFieldsAreRejectedWithoutServerError()
    {
        await LoginAsAdmin();
        using var supplier = await PostForm("/SupplyChain/AddSupplier", new Dictionary<string, string>(),
            tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.NotFound, supplier.StatusCode);

        using var rule = await PostForm("/SupplyChain/AddRule", new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["packagePattern"] = "Example.*",
            ["version"] = "1.*",
            ["source"] = "https://api.nuget.org/v3/index.json",
            ["expiresAtUtc"] = DateTime.UtcNow.AddDays(1).ToString("O")
        }, tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.BadRequest, rule.StatusCode);

        using var block = await PostForm("/SupplyChain/AddBlock", new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["packagePattern"] = "Example.Bad",
            ["version"] = "*"
        }, tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.BadRequest, block.StatusCode);
    }

    [TestMethod]
    public async Task TrustRuleRequiresAConfiguredPackageSource()
    {
        await LoginAsAdmin();
        var packageName = "Example.AllowedSource." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();


            await db.SaveChangesAsync();
        }
        var fields = new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["packagePattern"] = packageName,
            ["version"] = "1.*",
            ["source"] = "https://packages.example.invalid/v3/index.json",
            ["justification"] = "Approve only configured package mirrors",
            ["expiresAtUtc"] = DateTime.UtcNow.AddDays(1).ToString("O")
        };
        using var rejected = await PostForm("/SupplyChain/AddRule", fields, tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.BadRequest, rejected.StatusCode);
        StringAssert.Contains(await rejected.Content.ReadAsStringAsync(), "not permitted for trust rules");

        fields["source"] = "https://nuget.aiursoft.com/v3/index.json";
        using var accepted = await PostForm("/SupplyChain/AddRule", fields, tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.Redirect, accepted.StatusCode);
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var rules = await verifyDb.Rules.Where(r => r.Kind == RuleKind.Approval).Where(r => r.PackagePattern == packageName).ToListAsync();
        Assert.HasCount(1, rules);
        Assert.AreEqual("https://nuget.aiursoft.com/v3/index.json", rules[0].Source);
    }

    [TestMethod]
    public async Task CatalogDoesNotAdvertiseRulesFromRemovedSources()
    {
        await LoginAsAdmin();
        var permittedPackage = "Example.Permitted." + Guid.NewGuid().ToString("N");
        var removedPackage = "Example.Removed." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.AddRange([
                    new PackageRule
                    {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                        ApplicationId = null,
                        Ecosystem = "nuget", PackagePattern = permittedPackage, Version = "1.*",
                        Source = "https://nuget.aiursoft.com/v3/index.json",
                        Status = RuleStatus.Approved, ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
                    },
                    new PackageRule
                    {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                        ApplicationId = null,
                        Ecosystem = "nuget", PackagePattern = removedPackage, Version = "1.*",
                        Source = "https://packages.example.invalid/v3/index.json",
                        Status = RuleStatus.Approved, ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
                    }
                ]);
            await db.SaveChangesAsync();
        }

        using var catalog = await Http.GetAsync("/SupplyChain/Index?tab=rules&ecosystem=nuget");
        catalog.EnsureSuccessStatusCode();
        var html = await catalog.Content.ReadAsStringAsync();
        StringAssert.Contains(html, permittedPackage);
        Assert.IsFalse(html.Contains(removedPackage, StringComparison.Ordinal));

        var lookup = "/SupplyChain/Index?tab=rules&ecosystem=nuget&lookupName=" + Uri.EscapeDataString(removedPackage) +
                     "&lookupVersion=1.0.0&lookupSource=" +
                     Uri.EscapeDataString("https://packages.example.invalid/v3/index.json");
        using var result = await Http.GetAsync(lookup);
        result.EnsureSuccessStatusCode();
        StringAssert.Contains(await result.Content.ReadAsStringAsync(), "Source not permitted");

        var preview = "/SupplyChain/PreviewRule?ecosystem=nuget&packagePattern=" +
                      Uri.EscapeDataString(removedPackage) + "&version=1.*&source=" +
                      Uri.EscapeDataString("https://packages.example.invalid/v3/index.json");
        using var previewResult = await Http.GetAsync(preview);
        Assert.AreEqual(HttpStatusCode.BadRequest, previewResult.StatusCode);
    }

    [TestMethod]
    public async Task DirectRequestBlockExplainsRuleReasonAndIntroductionPath()
    {
        var packageName = "Example.DirectBlock." + Guid.NewGuid().ToString("N");
        var pattern = packageName + "*";
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = pattern,
                Version = "1.*",
                Justification = "Company policy forbids this package"
            });
            await db.SaveChangesAsync();
        }
        await LoginAsAdmin();
        using var response = await PostForm("/DependencyRequests/Submit", new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["source"] = "https://nuget.aiursoft.com/v3/index.json",
            ["directPackages"] = packageName + "@1.2.3",
            ["justification"] = "Verify direct blocklist explanation"
        }, tokenUrl: "/DependencyRequests/Index");
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        var message = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(message, packageName + "@1.2.3");
        StringAssert.Contains(message, pattern + " @ 1.*");
        StringAssert.Contains(message, "Introduction path: " + packageName);
        StringAssert.Contains(message, "Company policy forbids this package");
    }

    [TestMethod]
    public async Task EmployeeRequestRejectsMutableNpmTagsAndVersionRanges()
    {
        await LoginAsAdmin();
        foreach (var requestedVersion in new[] { "latest", "^1.0.0", "1.0", "file:local" })
        {
            using var response = await PostForm("/DependencyRequests/Submit", new Dictionary<string, string>
            {
                ["ecosystem"] = "npm",
                ["source"] = "https://npm.aiursoft.com",
                ["directPackages"] = "example@" + requestedVersion,
                ["justification"] = "Ensure the requested package version is exact"
            }, tokenUrl: "/DependencyRequests/Index");
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, requestedVersion);
        }
    }

    [TestMethod]
    public async Task EmployeeRequestRejectsCaseVariantDuplicateNuGetRoots()
    {
        var packageName = "Example.Duplicate." + Guid.NewGuid().ToString("N");
        await LoginAsAdmin();
        using var response = await PostForm("/DependencyRequests/Submit", new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["source"] = "https://nuget.aiursoft.com/v3/index.json",
            ["directPackages"] = packageName + "@1.0.0\n" + packageName.ToLowerInvariant() + "@1.0.0",
            ["justification"] = "The same NuGet package must not appear twice under different casing"
        }, tokenUrl: "/DependencyRequests/Index");
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.IsFalse(await db.DependencyApplications.AnyAsync(a => a.DirectPackages.Contains(packageName)));
    }

    [TestMethod]
    public async Task EmployeeRequestRejectsNuGetPathLikePackageNames()
    {
        await LoginAsAdmin();
        foreach (var name in new[] { "../outside", "Example/Child", ".", ".." })
        {
            using var response = await PostForm("/DependencyRequests/Submit", new Dictionary<string, string>
            {
                ["ecosystem"] = "nuget",
                ["source"] = "https://nuget.aiursoft.com/v3/index.json",
                ["directPackages"] = name + "@1.0.0",
                ["justification"] = "Reject package names that resemble filesystem paths"
            }, tokenUrl: "/DependencyRequests/Index");
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, name);
        }
    }

    [TestMethod]
    public async Task BlocklistHasSeparatePermissionAndShowsRecordedImpact()
    {
        var packageName = "Example.Blocked." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var userId = db.Users.Single(u => u.Email == "admin@default.com").Id;
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json"
            };
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "*",
                Justification = "Blocked for impact test",
                RequestedByUserId = userId
            });
            db.DependencyApplications.Add(new DependencyApplication
            {
                RequestedByUserId = userId,
                Ecosystem = "nuget",
                Source = artifact.Source,
                Packages = [new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, PackageVersion = artifact }]
            });
            db.BuildChecks.Add(new BuildCheck
            {
                RunId = Guid.NewGuid().ToString("N"),
                Project = "impact-test",
                Dependencies = [new BuildCheckDependency
                {
                    BuildCheckId = 0, PackageVersionId = null,
                    Ecosystem = "nuget", Name = packageName, Version = "1.0.0",
                    Source = artifact.Source
                }]
            });
            await db.SaveChangesAsync();
        }
        await RegisterAndLoginAsync();
        using (var denied = await Http.GetAsync("/SupplyChain/Blocklist?ecosystem=nuget"))
            Assert.AreNotEqual(HttpStatusCode.OK, denied.StatusCode);
        await LoginAsAdmin();
        using var page = await Http.GetAsync("/SupplyChain/Blocklist?ecosystem=nuget");
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        StringAssert.Contains(html, packageName);
        StringAssert.Contains(html, "1 artifacts");
        StringAssert.Contains(html, "1 applications");
        StringAssert.Contains(html, "1 CI check runs");
    }

    [TestMethod]
    public async Task RulePreviewShowsOnlyKnownMatchesAndRequiresRulePermission()
    {
        var root = "Example.Preview" + Guid.NewGuid().ToString("N");
        const string source = "https://api.nuget.org/v3/index.json";
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.PackageVersions.AddRange(
                new PackageVersion { Ecosystem = "nuget", Name = root + ".Child", Version = "1.2.0", Source = source },
                new PackageVersion { Ecosystem = "nuget", Name = root + ".Child", Version = "2.0.0", Source = source },
                new PackageVersion { Ecosystem = "nuget", Name = root, Version = "1.2.0", Source = source },
                new PackageVersion { Ecosystem = "nuget", Name = root + ".OtherSource", Version = "1.2.0", Source = "https://other.example/v3/index.json" });
            await db.SaveChangesAsync();
        }
        var url = "/SupplyChain/PreviewRule?ecosystem=nuget&packagePattern=" +
                  Uri.EscapeDataString(root + ".Child") + "&version=1.*&source=" + Uri.EscapeDataString(source);
        await RegisterAndLoginAsync();
        using (var denied = await Http.GetAsync(url))
            Assert.AreNotEqual(HttpStatusCode.OK, denied.StatusCode);
        await LoginAsAdmin();
        using var response = await Http.GetAsync(url);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, root + ".Child");
        Assert.DoesNotContain(root + ".OtherSource", html);
        Assert.DoesNotContain("2.0.0</code>", html);
        Assert.DoesNotContain("<code>" + root + "</code>", html);
        StringAssert.Contains(html, "No package is approved by viewing this page.");
    }

    [TestMethod]
    public async Task CheckApiDoesNotAcceptAnInteractiveAdminWithoutCiCredential()
    {
        await LoginAsAdmin();
        using var response = await Http.PostAsJsonAsync("/api/check", new
        {
            dependencies = new[]
            {
                new { ecosystem = "nuget", name = "Example", version = "1.0.0",
                    source = "https://api.nuget.org/v3/index.json", sha256 = new string('a', 64) }
            },
            runId = Guid.NewGuid().ToString("N"),
            batchIndex = 0,
            batchCount = 1
        });
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task CheckApiRecordsVerifiedDependencyFreeProjectWithoutAllowingEmptyScanClaims()
    {
        await AddCheckKeyAsync("integration-check-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        using (var missingProject = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "baseline-batch-test",
            Dependencies = [],
            RunId = Guid.NewGuid().ToString("N")
        }))
            Assert.AreEqual(HttpStatusCode.BadRequest, missingProject.StatusCode);
        using (var incompleteBatch = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "baseline-batch-test",
            Dependencies = [],
            ScannedProjectCount = 1,
            BatchCount = 2,
            RunId = Guid.NewGuid().ToString("N")
        }))
            Assert.AreEqual(HttpStatusCode.BadRequest, incompleteBatch.StatusCode);

        var runId = Guid.NewGuid().ToString("N");
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [],
            ScannedProjectCount = 2,
            RunId = runId,
            Project = "dependency-free-project"
        }))
        {
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Trusted);
            Assert.AreEqual(0, result.Decisions.Count);
        }
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var check = db.BuildChecks.Include(c => c.Dependencies).Single(c => c.RunId == runId);
        Assert.IsTrue(check.Trusted);
        Assert.AreEqual(2, check.ScannedProjectCount);
        Assert.AreEqual(0, check.Dependencies.Count());
        Assert.IsTrue(BuildCheckRun.IsComplete([check]));
        await LoginAsAdmin();
        using var page = await Http.GetAsync("/BuildChecks/Index?project=dependency-free-project");
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Scanned projects");
        StringAssert.Contains(html, "No external dependencies were found");
    }

    [TestMethod]
    public async Task AnonymousReviewRequiresEnabledSettingAndCannotDeclareBaseline()
    {
        Assert.AreEqual("False", SettingsMap.Definitions.Single(d => d.Key == SettingsMap.AllowAnonymousReview).DefaultValue);
        var request = new CheckRequest
        {
            Project = "self-reported-" + Guid.NewGuid().ToString("N"),
            RunId = Guid.NewGuid().ToString("N"),
            ScannedProjectCount = 1,
            Context = new CheckContext { Purpose = "review", Provider = "gitlab", IsAnonymous = false },
            Dependencies = [new Dependency { Ecosystem = "nuget", Name = "Unapproved.Anonymous." + Guid.NewGuid().ToString("N"),
                Version = "1.0.0", Source = "https://api.nuget.org/v3/index.json" }]
        };
        using (var disabled = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Unauthorized, disabled.StatusCode);
        using var settingsScope = Server!.Services.CreateScope();
        var settings = settingsScope.ServiceProvider.GetRequiredService<GlobalSettingsService>();
        await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "True");
        try
        {
            using (var allowed = await Http.PostAsJsonAsync("/api/check", request))
            {
                Assert.AreEqual(HttpStatusCode.OK, allowed.StatusCode);
                var result = await allowed.Content.ReadFromJsonAsync<CheckResponse>();
                Assert.IsNotNull(result);
                Assert.IsFalse(result.Trusted);
                StringAssert.Contains(result.Decisions.Single().Reason, "No approved trust rule");
            }
            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                Assert.IsFalse(await db.BuildChecks.AnyAsync(c => c.RunId == request.RunId));
                Assert.IsFalse(await db.PackageVersions.AnyAsync(a => a.Name == request.Dependencies[0].Name));
            }
            request.RunId = Guid.NewGuid().ToString("N");
            request.Context.Purpose = "baseline";
            using (var baseline = await Http.PostAsJsonAsync("/api/check", request))
                Assert.AreEqual(HttpStatusCode.Unauthorized, baseline.StatusCode);
            using (var scope = Server!.Services.CreateScope())
                Assert.IsFalse(await scope.ServiceProvider.GetRequiredService<TemplateDbContext>()
                    .BuildChecks.AnyAsync(c => c.RunId == request.RunId));
            request.Context.Purpose = "review";
            Http.DefaultRequestHeaders.Add("X-S360-Key", "invalid-present-credential");
            using (var invalidKey = await Http.PostAsJsonAsync("/api/check", request))
                Assert.AreEqual(HttpStatusCode.Unauthorized, invalidKey.StatusCode);
            Http.DefaultRequestHeaders.Remove("X-S360-Key");
        }
        finally
        {
            Http.DefaultRequestHeaders.Remove("X-S360-Key");
            await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "False");
        }
        using (var disabledAgain = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Unauthorized, disabledAgain.StatusCode);
    }

    [TestMethod]
    public async Task OnlyDistinctBaselineCredentialCanDeclareProductionUse()
    {
        await AddCheckKeyAsync("review-only-key");
        await AddCheckKeyAsync("protected-baseline-key", baseline: true);
        var runId = Guid.NewGuid().ToString("N");
        var request = new CheckRequest
        {
            Project = "baseline-auth-project",
            RunId = runId,
            ScannedProjectCount = 1,
            Context = new CheckContext { Purpose = "baseline" }
        };
        Http.DefaultRequestHeaders.Add("X-S360-Key", "review-only-key");
        using (var forbidden = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Forbidden, forbidden.StatusCode);
        using (var scope = Server!.Services.CreateScope())
            Assert.IsFalse(await scope.ServiceProvider.GetRequiredService<TemplateDbContext>()
                .BuildChecks.AnyAsync(c => c.RunId == runId));
        Http.DefaultRequestHeaders.Remove("X-S360-Key");
        Http.DefaultRequestHeaders.Add("X-S360-Key", "protected-baseline-key");
        using (var accepted = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, accepted.StatusCode);
        using (var scope = Server!.Services.CreateScope())
        {
            var check = await scope.ServiceProvider.GetRequiredService<TemplateDbContext>()
                .BuildChecks.SingleAsync(c => c.RunId == runId);
            Assert.AreEqual("baseline", BuildCheckRun.Purpose(check.ContextJson));
        }
        request.RunId = Guid.NewGuid().ToString("N");
        request.Project = " ";
        using (var unnamed = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, unnamed.StatusCode);
        request.Project = "baseline-auth-project";
        request.Context.Purpose = "production-typo";
        using (var invalid = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
        request.Context.Purpose = "baseline";
        request.Context.Ecosystem = "nuget";
        request.Dependencies = [new Dependency { Ecosystem = "npm", Name = "example", Version = "1.0.0",
            Source = "https://npm.aiursoft.com" }];
        using (var mixedScope = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, mixedScope.StatusCode);
        request.Dependencies.Clear();
        request.Context.Ecosystem = null;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var key = await db.ApiKeys.SingleAsync(k => k.Name == "protected-baseline-key");
            key.CanPublishBaselines = false;
            await db.SaveChangesAsync();
        }
        using (var revokedScope = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Forbidden, revokedScope.StatusCode);
        Http.DefaultRequestHeaders.Remove("X-S360-Key");
        Http.DefaultRequestHeaders.Add("X-S360-Key", "review-only-key");
        using (var disabled = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Forbidden, disabled.StatusCode);
    }

    [TestMethod]
    public async Task CheckApiRejectsMalformedConcretePackageIdentity()
    {
        await AddCheckKeyAsync("integration-check-key");
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var invalidDependencies = new[]
        {
            new Dependency { Ecosystem = "nuget", Name = "Example.Safe\n1.0.0", Version = "1.0.0" },
            new Dependency { Ecosystem = "nuget", Name = "Example.*", Version = "1.0.0" },
            new Dependency { Ecosystem = "nuget", Name = "Example.Safe", Version = "1.*" }
        };
        foreach (var dependency in invalidDependencies)
        {
            dependency.Source = "https://api.nuget.org/v3/index.json";

            using var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
            {
                Dependencies = [dependency],
                ScannedProjectCount = 1,
                RunId = Guid.NewGuid().ToString("N")
            });
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode,
                $"{dependency.Name}@{dependency.Version}");
        }
    }

    [TestMethod]
    public async Task CheckApiStoresCompleteGraphsAcrossBatchesAndRejectsMissingOrInventedPackages()
    {
        await AddCheckKeyAsync("integration-check-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var package = new Dependency
        {
            Ecosystem = "nuget",
            Name = "Graph." + Guid.NewGuid().ToString("N"),
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        var root = new DependencyGraphNode
        {
            Project = "src/App.csproj",
            Ecosystem = "nuget",
            Target = "net10.0",
            Id = "$root",
            Kind = "root",
            Children = ["package"]
        };
        var node = new DependencyGraphNode
        {
            Project = root.Project,
            Ecosystem = "nuget",
            Target = root.Target,
            Id = "package",
            Package = package
        };
        var request = new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "graph-" + Guid.NewGuid().ToString("N"),
            ScannedProjectCount = 1,
            Dependencies = [package],
            GraphNodes = [root],
            BatchCount = 2
        };
        using (var first = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        request.BatchIndex = 1;
        request.Dependencies = [];
        request.GraphNodes = null;
        using (var mixed = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, mixed.StatusCode);
        request.GraphNodes = [node];
        node.Children = ["missing"];
        using (var dangling = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, dangling.StatusCode);
        node.Children = [];
        node.Target = null!;
        using (var invalidNode = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, invalidNode.StatusCode);
        node.Target = root.Target;
        using (var last = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, last.StatusCode, await last.Content.ReadAsStringAsync());
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var stored = db.BuildChecks.Where(c => c.RunId == request.RunId).ToList();
            Assert.AreEqual(2, stored.Count);
            Assert.IsTrue(BuildCheckRun.IsComplete(stored));
            Assert.IsTrue(stored.All(c => c.GraphJson != null));
            Assert.AreEqual(1, db.BuildCheckDependencies.Count(d => stored.Select(c => c.Id).Contains(d.BuildCheckId)));
        }
        request.RunId = Guid.NewGuid().ToString("N"); request.BatchIndex = 0; request.BatchCount = 1;
        request.GraphNodes = [root, node];
        using (var invented = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, invented.StatusCode);
        request.Dependencies = [package]; request.GraphNodes = [root]; root.Children = [];
        using (var missingPackage = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, missingPackage.StatusCode);
        request.GraphNodes = [root, node]; request.ScannedProjectCount = 2;
        using (var missingManifest = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, missingManifest.StatusCode);
    }

    [TestMethod]
    public async Task SolutionReportsKeepSiblingProjectsAndRejectBrokenFinalBatch()
    {
        await AddCheckKeyAsync("solution-report-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "solution-report-key");
        var package = new Dependency
        {
            Ecosystem = "nuget",
            Name = "Solution.Unapproved",
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        var packageId = SolutionDependencyGraph.PackageId(package);
        var repository = "company/" + Guid.NewGuid().ToString("N");
        var request = new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline", Ecosystem = "nuget", Repository = repository, SolutionPath = "Product.sln" },
            ScannedProjectCount = 2,
            BatchCount = 2,
            Dependencies = [package],
            SolutionGraph = new SolutionDependencyGraph
            {
                SolutionPath = "Product.sln",
                Nodes = [new() { Id = "project:Safe.csproj", ProjectPath = "Safe.csproj", IsSolutionMember = true },
                    new() { Id = "project:SqlServer.csproj", ProjectPath = "SqlServer.csproj", IsSolutionMember = true }],
                Contexts = [new() { ProjectPath = "Safe.csproj", Target = "net10.0" }]
            }
        };
        using (var first = await Http.PostAsJsonAsync("/api/check", request))
        {
            Assert.AreEqual(HttpStatusCode.OK, first.StatusCode, await first.Content.ReadAsStringAsync());
            Assert.IsFalse((await first.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
        }
        request.BatchIndex = 1;
        request.Dependencies = [];
        request.SolutionGraph.Nodes = [new() { Id = packageId, Package = package }];
        request.SolutionGraph.Contexts = [new() { ProjectPath = "SqlServer.csproj", Target = "net10.0", Edges = [
            new() { ParentId = "project:SqlServer.csproj", ChildId = "missing" }] }];
        using (var broken = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, broken.StatusCode);
        request.SolutionGraph.Contexts[0].Edges[0].ChildId = packageId;
        using (var last = await Http.PostAsJsonAsync("/api/check", request))
        {
            Assert.AreEqual(HttpStatusCode.OK, last.StatusCode, await last.Content.ReadAsStringAsync());
            Assert.IsFalse((await last.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
        }
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var checks = await db.BuildChecks.Where(c => c.RunId == request.RunId).ToListAsync();
        Assert.HasCount(2, checks);
        Assert.IsTrue(BuildCheckRun.IsComplete(checks));
        Assert.IsTrue(checks.All(c => c.Project == repository + "//Product.sln"));
        var view = new Models.SupplyChainViewModels.InventoryViewModel
        { Tab = "projects", Scope = "baseline", Ecosystem = "nuget", Project = repository + "//Product.sln" };
        await scope.ServiceProvider.GetRequiredService<CatalogInventoryService>().PopulateAsync(view);
        var solution = view.Projects.Single().Solution!;
        Assert.IsNotNull(solution);
        Assert.AreEqual(repository, solution.Repository);
        Assert.HasCount(2, solution.Graph.Nodes.Where(n => n.ProjectPath != null).ToList());
        Assert.AreEqual("SqlServer.csproj", solution.Graph.PathsTo(new HashSet<string> { packageId }).Single().ProjectPath);
        await LoginAsAdmin();
        using var redirect = await Http.GetAsync("/SupplyChain?tab=projects&project=" + Uri.EscapeDataString(repository));
        Assert.AreEqual(HttpStatusCode.Redirect, redirect.StatusCode);
        StringAssert.Contains(Uri.UnescapeDataString(redirect.Headers.Location!.OriginalString), repository + "//Product.sln");
        using var page = await Http.GetAsync(redirect.Headers.Location);
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Project dependencies");
        StringAssert.Contains(html, "s360-graph-show-risks");
        StringAssert.Contains(html, "id=\"s360-solution-module\"");
        StringAssert.Contains(html, "Direct dependencies only");
        StringAssert.Contains(html, "Safe.csproj");
        StringAssert.Contains(html, "SqlServer.csproj");
        StringAssert.Contains(html, "<label hidden=\"hidden\">Manifest and target");
    }

    [TestMethod]
    public async Task SolutionsInOneRepositoryHaveIndependentBaselinesAndReviewNeverReplacesThem()
    {
        await AddCheckKeyAsync("solution-identity-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "solution-identity-key");
        var repository = "company/" + Guid.NewGuid().ToString("N");
        var request = new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline", Ecosystem = "nuget", Repository = repository },
            ScannedProjectCount = 1,
            SolutionGraph = new SolutionDependencyGraph
            {
                Nodes = [new() { Id = "project:App.csproj", ProjectPath = "App.csproj", IsSolutionMember = true }],
                Contexts = [new() { ProjectPath = "App.csproj", Target = "net10.0" }]
            }
        };
        foreach (var path in new[] { "first/Product.sln", "second/Product.sln" })
        {
            request.RunId = Guid.NewGuid().ToString("N");
            request.Context.SolutionPath = path;
            request.SolutionGraph.SolutionPath = path;
            using var response = await Http.PostAsJsonAsync("/api/check", request);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, await response.Content.ReadAsStringAsync());
        }
        request.RunId = Guid.NewGuid().ToString("N");
        request.Context.Purpose = "review";
        using (var review = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, review.StatusCode, await review.Content.ReadAsStringAsync());
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var identities = await db.BuildChecks.Where(c => c.Project!.StartsWith(repository + "//")).Select(c => c.Project).ToListAsync();
        CollectionAssert.AreEquivalent(new[] { repository + "//first/Product.sln", repository + "//second/Product.sln" }, identities);
        Assert.IsFalse(await db.BuildChecks.AnyAsync(c => c.RunId == request.RunId));
    }

    [TestMethod]
    public async Task CheckApiRejectsConflictingBatchMetadataWithinOneRun()
    {
        await AddCheckKeyAsync("integration-check-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var runId = Guid.NewGuid().ToString("N");
        var dependency = new Dependency
        {
            Ecosystem = "nuget",
            Name = "Unapproved." + Guid.NewGuid().ToString("N"),
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        using (var first = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 0,
            BatchCount = 2,
            Project = "first-project",
            Commit = "first-commit"
        }))
            Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        using var conflicting = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 1,
            BatchCount = 2,
            Project = "different-project",
            Commit = "first-commit"
        });
        Assert.AreEqual(HttpStatusCode.BadRequest, conflicting.StatusCode);
        using var inconsistentScan = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [dependency],
            ScannedProjectCount = 2,
            RunId = runId,
            BatchIndex = 1,
            BatchCount = 2,
            Project = "first-project",
            Commit = "first-commit"
        });
        Assert.AreEqual(HttpStatusCode.BadRequest, inconsistentScan.StatusCode);
        using var inconsistentContext = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 1,
            BatchCount = 2,
            Project = "first-project",
            Commit = "first-commit",
            Context = new CheckContext { Purpose = "baseline", Provider = "gitlab", Ref = "master", DefaultBranch = "master", PipelineSource = "push" }
        });
        Assert.AreEqual(HttpStatusCode.BadRequest, inconsistentContext.StatusCode);
        await LoginAsAdmin();
        using var page = await Http.GetAsync("/BuildChecks/Index?project=first-project");
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        StringAssert.Contains(html, runId);
        StringAssert.Contains(html, "Incomplete run");
    }

    [TestMethod]
    public async Task CheckApiRejectsOutOfOrderBatchesWithoutRecordingThem()
    {
        await AddCheckKeyAsync("integration-check-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var runId = Guid.NewGuid().ToString("N");
        var dependency = new Dependency
        {
            Ecosystem = "nuget",
            Name = "Example.OutOfOrder." + Guid.NewGuid().ToString("N"),
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        var request = new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 1,
            BatchCount = 2,
            Project = "out-of-order-project"
        };
        using (var outOfOrder = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.BadRequest, outOfOrder.StatusCode);

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.IsFalse(db.BuildChecks.Any(c => c.RunId == runId));
        }

        request.BatchIndex = 0;
        using (var first = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        request.BatchIndex = 1;
        using (var second = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, second.StatusCode);
    }

    [TestMethod]
    public async Task FinalBatchRejectsAnEarlierPackageBlockedBetweenBatches()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        const string key = "integration-batch-policy-key";
        var prefix = "Example.BatchPolicy." + Guid.NewGuid().ToString("N");
        var first = new Dependency
        {
            Ecosystem = "nuget",
            Name = prefix + ".First",
            Version = "1.0.0",
            Source = source
        };
        var second = new Dependency
        {
            Ecosystem = "nuget",
            Name = prefix + ".Second",
            Version = "1.0.0",
            Source = source
        };
        var checkedAtUtc = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            foreach (var dependency in new[] { first, second })
            {
                db.Rules.Add(new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Ecosystem = dependency.Ecosystem,
                    PackagePattern = dependency.Name,
                    Version = dependency.Version,
                    Source = dependency.Source,
                    Status = RuleStatus.Approved,
                    ExpiresAtUtc = checkedAtUtc.AddDays(1)
                });
                db.PackageVersions.Add(new PackageVersion
                {
                    Ecosystem = dependency.Ecosystem,
                    Name = dependency.Name,
                    Version = dependency.Version,
                    Source = dependency.Source,
                    LastCheckedAtUtc = checkedAtUtc
                });
            }
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastAttemptAtUtc = checkedAtUtc.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = checkedAtUtc.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
        await AddCheckKeyAsync(key, baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", key);
        var runId = Guid.NewGuid().ToString("N");
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "baseline-batch-test",
            Dependencies = [first],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 0,
            BatchCount = 2
        }))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsTrue((await response.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = first.Name,
                Version = "*",
                Justification = "Blocked after the first batch was checked"
            });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "baseline-batch-test",
            Dependencies = [second],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 1,
            BatchCount = 2
        }))
        {
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Trusted);
            Assert.IsTrue(result.Decisions.Single().Trusted);
            StringAssert.Contains(result.Message, first.Name);
            StringAssert.Contains(result.Message, "Blocked after the first batch was checked");
        }
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var batches = await verifyDb.BuildChecks.Where(c => c.RunId == runId).ToListAsync();
        Assert.IsTrue(BuildCheckRun.IsComplete(batches));
        Assert.IsFalse(batches.Single(c => c.BatchIndex == 1).Trusted);
    }

    [TestMethod]
    public async Task FinalBatchRejectsAnEarlierPackageWhoseSourceWasRemoved()
    {
        const string removedSource = "https://api.nuget.org/v3/index.json";
        const string remainingSource = "https://nuget.aiursoft.com/v3/index.json";
        const string key = "integration-batch-source-key";
        var prefix = "Example.BatchSource." + Guid.NewGuid().ToString("N");
        var first = new Dependency
        {
            Ecosystem = "nuget",
            Name = prefix + ".First",
            Version = "1.0.0",
            Source = removedSource
        };
        var second = new Dependency
        {
            Ecosystem = "nuget",
            Name = prefix + ".Second",
            Version = "1.0.0",
            Source = remainingSource
        };
        var checkedAt = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            foreach (var dependency in new[] { first, second })
            {
                db.Rules.Add(new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Ecosystem = dependency.Ecosystem,
                    PackagePattern = dependency.Name,
                    Version = dependency.Version,
                    Source = dependency.Source,
                    Status = RuleStatus.Approved,
                    ExpiresAtUtc = checkedAt.AddDays(1)
                });
                db.PackageVersions.Add(new PackageVersion
                {
                    Ecosystem = dependency.Ecosystem,
                    Name = dependency.Name,
                    Version = dependency.Version,
                    Source = dependency.Source,
                    LastCheckedAtUtc = checkedAt
                });
            }
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastAttemptAtUtc = checkedAt.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = checkedAt.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
        var configuration = GetService<IConfiguration>();
        await AddCheckKeyAsync(key, baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", key);
        var runId = Guid.NewGuid().ToString("N");
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Project = "baseline-batch-test",
            Dependencies = [first],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 0,
            BatchCount = 2
        }))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsTrue((await response.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
        }

        var originalSource = configuration["SupplyChain:NuGetSources:1"];
        configuration["SupplyChain:NuGetSources:1"] = "https://replacement.example.com/v3/index.json";
        try
        {
            using var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
            {
                Context = new CheckContext { Purpose = "baseline" },
                Project = "baseline-batch-test",
                Dependencies = [second],
                ScannedProjectCount = 1,
                RunId = runId,
                BatchIndex = 1,
                BatchCount = 2
            });
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Trusted);
            Assert.IsTrue(result.Decisions.Single().Trusted);
            StringAssert.Contains(result.Message, first.Name);
            StringAssert.Contains(result.Message, removedSource);
        }
        finally
        {
            configuration["SupplyChain:NuGetSources:1"] = originalSource;
        }
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var batches = await verifyDb.BuildChecks.Where(c => c.RunId == runId).ToListAsync();
        Assert.IsTrue(BuildCheckRun.IsComplete(batches));
        Assert.IsFalse(batches.Single(c => c.BatchIndex == 1).Trusted);
    }

    [TestMethod]
    public async Task CheckApiRejectsDuplicateBatchWithoutAddingAnotherRecord()
    {
        await AddCheckKeyAsync("integration-check-key", baseline: true);
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var runId = Guid.NewGuid().ToString("N");
        var request = new CheckRequest
        {
            Context = new CheckContext { Purpose = "baseline" },
            Dependencies = [new Dependency
            {
                Ecosystem = "nuget", Name = "Unapproved." + Guid.NewGuid().ToString("N"),
                Version = "1.0.0", Source = "https://api.nuget.org/v3/index.json"
            }],
            ScannedProjectCount = 1,
            RunId = runId,
            BatchIndex = 0,
            BatchCount = 2,
            Project = "duplicate-batch-test"
        };
        using (var first = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        using (var duplicate = await Http.PostAsJsonAsync("/api/check", request))
            Assert.AreEqual(HttpStatusCode.Conflict, duplicate.StatusCode);
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(1, db.BuildChecks.Count(c => c.RunId == runId));
        Assert.IsFalse(BuildCheckRun.IsComplete(db.BuildChecks.Where(c => c.RunId == runId).ToList()));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ReviewQueriesRulesWithoutCreatingPackageOrProjectRecords(bool anonymous)
    {
        var suffix = Guid.NewGuid().ToString("N");
        var project = "review-only-" + suffix;
        var dependency = new Dependency
        {
            Ecosystem = "nuget",
            Name = "Unapproved." + suffix,
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

        db.Rules.Add(new PackageRule
        {
            RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
            ApplicationId = null,
            Ecosystem = dependency.Ecosystem,
            PackagePattern = dependency.Name + ".Approved",
            Version = "1.*",
            Source = dependency.Source,
            Status = RuleStatus.Approved
        });
        (await db.VulnerabilitySyncStates.SingleAsync()).LastSuccessAtUtc = null;
        await db.SaveChangesAsync();
        var settings = scope.ServiceProvider.GetRequiredService<GlobalSettingsService>();
        if (anonymous) await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "True");
        else
        {
            await AddCheckKeyAsync("review-key");
            Http.DefaultRequestHeaders.Add("X-S360-Key", "review-key");
        }
        var request = new CheckRequest
        {
            Project = project,
            ScannedProjectCount = 1,
            Dependencies = [dependency, new Dependency { Ecosystem = dependency.Ecosystem,
                Name = dependency.Name + ".Approved", Version = dependency.Version,
                Source = dependency.Source}],
            BatchCount = 2
        };
        try
        {
            // Replaying or checking another batch must not create persistent run state.
            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var response = await Http.PostAsJsonAsync("/api/check", request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
                Assert.IsNotNull(result);
                Assert.IsFalse(result.Trusted);
                StringAssert.Contains(result.Decisions[0].Reason, "No approved trust rule");
                Assert.IsFalse(result.Decisions[0].PendingVerification);
                Assert.IsTrue(result.Decisions[1].PendingVerification);
            }
            request.BatchIndex = 1;
            request.Dependencies = [];
            request.GraphNodes = [new DependencyGraphNode { Project = "src/Test.csproj", Ecosystem = "nuget", Id = "$root", Kind = "root" }];
            using var graphBatch = await Http.PostAsJsonAsync("/api/check", request);
            graphBatch.EnsureSuccessStatusCode();
            Assert.IsTrue((await graphBatch.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
            Assert.IsFalse(await db.PackageVersions.AnyAsync(a => a.Name.StartsWith(dependency.Name)));
            Assert.IsFalse(await db.BuildChecks.AnyAsync(c => c.RunId == request.RunId));
            Assert.IsFalse(await db.BuildCheckDependencies.AnyAsync(d => d.Name.StartsWith(dependency.Name)));
            Assert.IsTrue(GetService<Microsoft.Extensions.Caching.Memory.IMemoryCache>()
                .TryGetValue("s360-osv-audit-queued", out _));
            await LoginAsAdmin();
            foreach (var url in new[] { "/BuildChecks/Index", "/VulnerabilityAudit/Index?detailed=true",
                         "/SupplyChain?tab=projects&scope=review" })
            {
                using var page = await Http.GetAsync(url);
                page.EnsureSuccessStatusCode();
                Assert.DoesNotContain(project, await page.Content.ReadAsStringAsync());
            }
        }
        finally { await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "False"); }
    }

    [TestMethod]
    public async Task AnonymousReviewDoesNotQueueVersionsAndBoundsConcurrentRequests()
    {
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var settings = scope.ServiceProvider.GetRequiredService<GlobalSettingsService>();
        await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "True");
        var name = "Example.Admission." + Guid.NewGuid().ToString("N");

        db.Rules.Add(new PackageRule
        {
            RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
            ApplicationId = null,
            Ecosystem = "nuget",
            PackagePattern = name,
            Version = "1.*",
            Source = "https://api.nuget.org/v3/index.json",
            Status = RuleStatus.Approved
        });
        var completedAudit = await db.VulnerabilitySyncStates.SingleAsync();
        completedAudit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
        completedAudit.LastSuccessAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        var request = new CheckRequest
        {
            Project = name,
            ScannedProjectCount = 1,
            Dependencies = Enumerable.Range(0, 21).Select(i => new Dependency
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0." + i,
                Source = "https://api.nuget.org/v3/index.json"
            }).ToList()
        };
        try
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var response = await Http.PostAsJsonAsync("/api/check", request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
                Assert.IsNotNull(result);
                Assert.IsTrue(result.Trusted, string.Join("; ", result.Decisions.Select(d => d.Reason)));
                Assert.IsTrue(result.Decisions.All(d => d.Trusted && !d.PendingVerification));
                Assert.AreEqual(0, await db.PackageVersions.CountAsync(a => a.Name == name));
            }
            var admission = scope.ServiceProvider.GetRequiredService<ReviewAdmission>();
            for (var i = 0; i < 4; i++) Assert.IsTrue(admission.AnonymousReviews.Wait(0));
            try
            {
                using var busy = await Http.PostAsJsonAsync("/api/check", request);
                Assert.AreEqual(HttpStatusCode.TooManyRequests, busy.StatusCode);
                Assert.IsNotNull(busy.Headers.RetryAfter);
            }
            finally { admission.AnonymousReviews.Release(4); }
            Assert.IsFalse(await db.BuildChecks.AnyAsync(c => c.Project == name));
        }
        finally { await settings.UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "False"); }
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ReviewChecksApprovedArtifactVulnerabilityAndAbsoluteBlock(bool anonymous)
    {
        var packageName = "Example." + Guid.NewGuid().ToString("N");
        await AddCheckKeyAsync("integration-check-key");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();


            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                LastCheckedAtUtc = DateTime.UtcNow
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
        }
        if (anonymous)
        {
            using var scope = Server!.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<GlobalSettingsService>()
                .UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "True");
        }
        else Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        var dependency = new Dependency
        {
            Ecosystem = "nuget",
            Name = packageName,
            Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json"
        };
        var unconfiguredRunId = Guid.NewGuid().ToString("N");
        using (var unconfigured = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Dependencies = [new Dependency
                   {
                       Ecosystem = dependency.Ecosystem, Name = dependency.Name,
                       Version = dependency.Version, Source = "https://127.0.0.1"
                   }, dependency],
            ScannedProjectCount = 1,
            RunId = unconfiguredRunId
        }))
        {
            unconfigured.EnsureSuccessStatusCode();
            var denial = await unconfigured.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(denial);
            Assert.IsFalse(denial.Trusted);
            Assert.AreEqual(2, denial.Decisions.Count);
            var decision = denial.Decisions[0];
            Assert.IsFalse(decision.Trusted);
            Assert.AreEqual(packageName, decision.Dependency.Name);
            Assert.AreEqual("https://127.0.0.1", decision.Dependency.Source);
            StringAssert.Contains(decision.Reason, "Package source is not permitted");
            Assert.IsTrue(denial.Decisions[1].Trusted);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.IsFalse(await db.BuildChecks.AnyAsync(c => c.RunId == unconfiguredRunId));
            Assert.IsFalse(await db.PackageVersions.AnyAsync(a => a.Name == packageName &&
                a.Source == "https://127.0.0.1"));
        }
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = Guid.NewGuid().ToString("N")
        }))
        {
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Trusted);
            Assert.IsTrue(result.Decisions.Single().Trusted);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = await db.PackageVersions.SingleAsync(a => a.Name == packageName);
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-fixture-" + Guid.NewGuid().ToString("N"),
                Summary = "Test-only advisory",
                Matches = [new VulnerabilityMatch { VulnerabilityId = 0, PackageVersionId = artifact.Id }]
            });
            await db.SaveChangesAsync();
        }
        using (var affected = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        { Dependencies = [dependency], ScannedProjectCount = 1, RunId = Guid.NewGuid().ToString("N") }))
        {
            affected.EnsureSuccessStatusCode();
            var decision = await affected.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(decision);
            Assert.IsFalse(decision.Trusted);
            StringAssert.Contains(decision.Decisions.Single().Reason, "known active vulnerability");
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "*",
                Status = RuleStatus.Approved,
                Justification = "Security incident"
            });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
        {
            Dependencies = [dependency],
            ScannedProjectCount = 1,
            RunId = Guid.NewGuid().ToString("N")
        }))
        {
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadFromJsonAsync<CheckResponse>();
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Trusted);
            StringAssert.Contains(result.Decisions.Single().Reason, "Absolutely blocked");
        }
        await LoginAsAdmin();
        using var history = await Http.GetAsync("/BuildChecks/Index");
        history.EnsureSuccessStatusCode();
        var html = await history.Content.ReadAsStringAsync();
        Assert.DoesNotContain(packageName, html);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.IsFalse(await db.BuildCheckDependencies.AnyAsync(d => d.Name == packageName));
            Assert.AreEqual(1, await db.PackageVersions.CountAsync(a => a.Name == packageName));
        }
        using var settingsScope = Server!.Services.CreateScope();
        await settingsScope.ServiceProvider.GetRequiredService<GlobalSettingsService>()
            .UpdateSettingAsync(SettingsMap.AllowAnonymousReview, "False");
    }

    [TestMethod]
    public async Task CiKeyAloneCannotUseHumanApprovalPages()
    {
        await AddCheckKeyAsync("integration-check-key");
        Http.DefaultRequestHeaders.Add("X-S360-Key", "integration-check-key");
        using var review = await Http.GetAsync("/DependencyReviews/Index");
        Assert.AreEqual(HttpStatusCode.Redirect, review.StatusCode);
        using var block = await Http.PostAsync("/SupplyChain/AddBlock", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["packagePattern"] = "Example.Bad",
            ["version"] = "*",
            ["reason"] = "Unsafe package"
        }));
        Assert.AreNotEqual(HttpStatusCode.OK, block.StatusCode);
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.IsFalse(db.Rules.Where(r => r.Kind == RuleKind.Block).Any(b => b.PackagePattern == "Example.Bad"));
    }

    [TestMethod]
    public async Task CatalogNeverListsRevokedOrBlockedArtifactAsAvailable()
    {
        var packageName = "Example." + Guid.NewGuid().ToString("N");
        var rulePattern = packageName;
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = rulePattern,
                Version = "1.*",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                LastCheckedAtUtc = DateTime.UtcNow
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            response.EnsureSuccessStatusCode();
            StringAssert.Contains(await response.Content.ReadAsStringAsync(), packageName);
        }
        var lookupUrl = "/SupplyChain/Index?tab=rules&catalogView=artifacts&lookupName=" + packageName + "&lookupVersion=1.1.0&lookupSource=" +
                        Uri.EscapeDataString("https://api.nuget.org/v3/index.json");
        using (var response = await Http.GetAsync(lookupUrl))
        {
            response.EnsureSuccessStatusCode();
            StringAssert.Contains(await response.Content.ReadAsStringAsync(), "Allowed");
        }
        var knownLookupUrl = "/SupplyChain/Index?tab=rules&catalogView=artifacts&lookupName=" + packageName +
                             "&lookupVersion=1.0.0&lookupSource=" +
                             Uri.EscapeDataString("https://api.nuget.org/v3/index.json");
        using (var response = await Http.GetAsync(knownLookupUrl))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "Allowed");
            Assert.DoesNotContain("Recorded SHA-256", html);
            StringAssert.Contains(html, "Package files are downloaded and checked by your registry");
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Revoked
            });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            response.EnsureSuccessStatusCode();
            Assert.DoesNotContain("<code>" + packageName + "</code>", await response.Content.ReadAsStringAsync());
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Where(r => r.Kind == RuleKind.Approval).Single(r => r.PackagePattern == packageName && r.Version == "1.0.0").Status = RuleStatus.Approved;
            await db.SaveChangesAsync();
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "*",
                Status = RuleStatus.Approved,
                Justification = "Blocked for regression test"
            });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("<code>" + packageName + "</code>", html);
            var rulesHtml = await Http.GetStringAsync("/SupplyChain/Index?tab=rules&query=" + packageName);
            StringAssert.Contains(rulesHtml, "Overridden by blocklist");
            StringAssert.Contains(rulesHtml, "Blocked for regression test");
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Where(r => r.Kind == RuleKind.Block).Single(b => b.PackagePattern == packageName).Status = RuleStatus.Revoked;
            db.Rules.Where(r => r.Kind == RuleKind.Approval).Single(r => r.PackagePattern == rulePattern && r.Version == "1.*").Status = RuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("<code>" + packageName + "</code>", html);
        }
    }

    [TestMethod]
    public async Task CatalogKeepsPublishedArtifactsAfterRefreshFailureButHidesExpiredResults()
    {
        await LoginAsAdmin();
        var packageName = "Example.AuditFailure." + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        int artifactId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                LastCheckedAtUtc = now
            };
            db.PackageVersions.Add(artifact);
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "1.0.0",
                Source = artifact.Source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = now.AddDays(1)
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastAttemptAtUtc = now;
            audit.LastSuccessfulAttemptAtUtc = now;
            audit.LastError = null;
            await db.SaveChangesAsync();
            artifactId = artifact.Id;
        }

        var url = "/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + Uri.EscapeDataString(packageName);
        using (var response = await Http.GetAsync(url))
        {
            response.EnsureSuccessStatusCode();
            StringAssert.Contains(await response.Content.ReadAsStringAsync(), "<code>" + packageName + "</code>");
        }

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var audit = await db.VulnerabilitySyncStates.FirstAsync();
            audit.LastAttemptAtUtc = now.AddSeconds(2);
            audit.LastError = "Upstream audit unavailable";
            await db.SaveChangesAsync();
        }

        try
        {
            using (var response = await Http.GetAsync(url))
            {
                response.EnsureSuccessStatusCode();
                var html = await response.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "latest vulnerability synchronization failed");
                StringAssert.Contains(html, "<code>" + packageName + "</code>");
            }
            using var details = await Http.GetAsync($"/SupplyChain/Details/{artifactId}");
            Assert.AreEqual(HttpStatusCode.OK, details.StatusCode);

            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var audit = await db.VulnerabilitySyncStates.FirstAsync();
                audit.LastSuccessAtUtc = now.AddHours(-13);
                audit.LastAttemptAtUtc = audit.LastSuccessAtUtc;
                audit.LastSuccessfulAttemptAtUtc = audit.LastSuccessAtUtc;
                audit.LastError = null;
                await db.SaveChangesAsync();
            }
            using (var stale = await Http.GetAsync(url))
            {
                stale.EnsureSuccessStatusCode();
                var html = await stale.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "Vulnerability auditing is stale");
                Assert.DoesNotContain("<code>" + packageName + "</code>", html);
            }

            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var audit = await db.VulnerabilitySyncStates.FirstAsync();
                audit.LastSuccessAtUtc = null;
                audit.LastAttemptAtUtc = null;
                audit.LastSuccessfulAttemptAtUtc = null;
                await db.SaveChangesAsync();
            }
            using (var missing = await Http.GetAsync(url))
            {
                missing.EnsureSuccessStatusCode();
                var html = await missing.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "Vulnerability auditing has not completed yet");
                Assert.DoesNotContain("<code>" + packageName + "</code>", html);
            }
        }
        finally
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var audit = await db.VulnerabilitySyncStates.FirstAsync();
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastAttemptAtUtc = DateTime.UtcNow;
            audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
    }

    [TestMethod]
    public async Task CatalogDoesNotShowVersionExcludedByOverlappingRule()
    {
        var packageName = "Example.SupplierScope." + Guid.NewGuid().ToString("N");
        const string source = "https://api.nuget.org/v3/index.json";
        int artifactId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = DateTime.UtcNow
            };
            var allowed = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var excluded = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var vulnerability = new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-" + Guid.NewGuid().ToString("N"),
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.1"}]}]}]
                    """.Replace("PACKAGE", packageName, StringComparison.Ordinal)
            };
            db.PackageVersions.Add(artifact);
            db.Rules.AddRange(allowed, excluded);
            db.Vulnerabilities.Add(vulnerability);
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = excluded.Id,
                VulnerabilityId = vulnerability.Id,
                Justification = "This rule excludes the affected version"
            });
            await db.SaveChangesAsync();
            artifactId = artifact.Id;
        }
        await LoginAsAdmin();
        using (var all = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            all.EnsureSuccessStatusCode();
            Assert.DoesNotContain($"/SupplyChain/Details/{artifactId}", await all.Content.ReadAsStringAsync());
        }
        using var filtered = await Http.GetAsync($"/SupplyChain/Index?tab=rules&catalogView=artifacts&query={packageName}");
        filtered.EnsureSuccessStatusCode();
        Assert.DoesNotContain($"/SupplyChain/Details/{artifactId}", await filtered.Content.ReadAsStringAsync());
    }

    [TestMethod]
    public async Task CatalogDetailsShowCurrentEvidenceWithoutExposingRequestMetadata()
    {
        await LoginAsAdmin();
        var packageName = "Example.Detail." + Guid.NewGuid().ToString("N");
        var childName = "Example.Child." + Guid.NewGuid().ToString("N");
        var privateProject = "Private-project-" + Guid.NewGuid().ToString("N");
        int artifactId;
        int ruleId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = packageName,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json",
                LastCheckedAtUtc = DateTime.UtcNow
            };
            var child = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = childName,
                Version = "2.0.0",
                Source = "https://api.nuget.org/v3/index.json"
            };
            var rule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "1.0.0",
                Source = artifact.Source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
                Reviews = [new RuleChange { RuleId = 0, Decision = RuleStatus.Approved, ReviewedAtUtc = DateTime.UtcNow.AddDays(-1) }]
            };
            db.PackageVersions.AddRange(artifact, child);
            db.Rules.Add(rule);
            db.DependencyApplications.Add(new DependencyApplication
            {
                Ecosystem = "nuget",
                Source = artifact.Source,
                Status = ApplicationStatus.Approved,
                Project = privateProject,
                RequestedByUserId = db.Users.First().Id,
                Packages = [new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, PackageVersion = artifact, IsDirect = true }]
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
            artifactId = artifact.Id;
            ruleId = rule.Id;
        }
        using (var catalog = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName))
        {
            catalog.EnsureSuccessStatusCode();
            var html = await catalog.Content.ReadAsStringAsync();
            StringAssert.Contains(html, $"/SupplyChain/Details/{artifactId}");
            Assert.DoesNotContain("Pinned SHA-256", html);
            StringAssert.Contains(html, "Last checked");
            StringAssert.Contains(html, "data-utc-time=");
            Assert.IsFalse(html.Contains("Last checked (UTC)"));
        }
        using (var response = await Http.GetAsync($"/SupplyChain/Details/{artifactId}"))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(new string('d', 64), html);
            Assert.DoesNotContain(childName, html);
            StringAssert.Contains(html, "Matching authorization");
            StringAssert.Contains(html, "s360-concept-rail");
            Assert.DoesNotContain("Recorded relationship", html);
            Assert.DoesNotContain(privateProject, html);
        }
        var configuration = GetService<IConfiguration>();
        var originalSource = configuration["SupplyChain:NuGetSources:1"];
        configuration["SupplyChain:NuGetSources:1"] = "https://replacement.example.com/v3/index.json";
        try
        {
            using var catalog = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + packageName);
            catalog.EnsureSuccessStatusCode();
            Assert.DoesNotContain($"/SupplyChain/Details/{artifactId}",
                await catalog.Content.ReadAsStringAsync());
            using var removed = await Http.GetAsync($"/SupplyChain/Details/{artifactId}");
            Assert.AreEqual(HttpStatusCode.NotFound, removed.StatusCode);
        }
        finally { configuration["SupplyChain:NuGetSources:1"] = originalSource; }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "*",
                Justification = "Do not use this dependency"
            });
            await db.SaveChangesAsync();
        }
        using (var blocked = await Http.GetAsync($"/SupplyChain/Details/{artifactId}"))
            Assert.AreEqual(HttpStatusCode.NotFound, blocked.StatusCode);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Where(r => r.Kind == RuleKind.Block).Single(b => b.PackagePattern == packageName).Status = RuleStatus.Revoked;
            db.Rules.Where(r => r.Kind == RuleKind.Approval).Single(r => r.Id == ruleId).Status = RuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        using var revoked = await Http.GetAsync($"/SupplyChain/Details/{artifactId}");
        Assert.AreEqual(HttpStatusCode.NotFound, revoked.StatusCode);
    }

    [TestMethod]
    public async Task CatalogSearchesPastUnapprovedArtifactsBeforeLimitingResults()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var approvedName = "Z.Approved." + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.PackageVersions.AddRange(Enumerable.Range(0, 5001).Select(i => new PackageVersion
            {
                Ecosystem = "nuget",
                Name = $"A.Unapproved.{i:D4}",
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = now
            }));
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = approvedName,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = now
            });
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = approvedName,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = now.AddDays(1)
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = now.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = now.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = now.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = now.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        using var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&ecosystem=nuget");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "<code>" + approvedName + "</code>");
        Assert.DoesNotContain("A.Unapproved.0000</code>", html);
        Assert.DoesNotContain("Only the first 500 results are shown", html);
    }

    [TestMethod]
    public async Task CatalogIgnoresHistoricalFileCheckTimesWhenPolicyAuditIsCurrent()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var name = "Example.PartialAudit." + Guid.NewGuid().ToString("N");
        var checkedAtUtc = DateTime.UtcNow;
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = checkedAtUtc
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastSuccessAtUtc = checkedAtUtc.AddMinutes(-1);
            audit.LastAttemptAtUtc = checkedAtUtc;
            audit.LastSuccessfulAttemptAtUtc = checkedAtUtc;
            audit.LastError = "Later package query failed";
            await db.SaveChangesAsync();
        }
        var url = "/SupplyChain/Index?tab=rules&catalogView=artifacts&ecosystem=nuget&query=" + Uri.EscapeDataString(name);
        using (var pending = await Http.GetAsync(url))
        {
            pending.EnsureSuccessStatusCode();
            StringAssert.Contains(await pending.Content.ReadAsStringAsync(), "<code>" + name + "</code>");
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var audit = await db.VulnerabilitySyncStates.FirstAsync();
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
        using var completed = await Http.GetAsync(url);
        completed.EnsureSuccessStatusCode();
        StringAssert.Contains(await completed.Content.ReadAsStringAsync(), "<code>" + name + "</code>");
    }

    [TestMethod]
    public async Task CatalogGroupsRepeatedVersionObservations()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var name = "Example.Conflicting." + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = now.AddDays(1)
            });
            for (var i = 0; i < 2; i++)
                db.PackageVersions.Add(new PackageVersion
                {
                    Ecosystem = "nuget",
                    Name = name,
                    Version = "1.0.0",
                    Source = source,
                    LastCheckedAtUtc = now
                });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null) db.VulnerabilitySyncStates.Add(audit = new VulnerabilitySyncState());
            audit.LastAttemptAtUtc = now.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = now.AddMinutes(-1);
            audit.LastSuccessAtUtc = now;
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        using var response = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + name);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(html, "<a href=\"/SupplyChain/Details/").Count);
        using var lookup = await Http.GetAsync("/SupplyChain/Index?tab=rules&catalogView=artifacts&lookupName=" + name +
            "&lookupVersion=1.0.0&lookupSource=" + Uri.EscapeDataString(source));
        lookup.EnsureSuccessStatusCode();
        Assert.DoesNotContain("Conflicting package hashes", await lookup.Content.ReadAsStringAsync());
    }

    [TestMethod]
    public async Task CatalogLookupShowsVersionExclusionDespiteOverlappingApproval()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var name = "Example.Excluded." + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var excludedRule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "1.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = now.AddDays(1)
            };
            var alternateRule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = now.AddDays(1)
            };
            var advisory = new Vulnerability
            {
                SourceId = "GHSA-excluded-test",
                Ecosystem = "nuget",
                PackageName = name,
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE_NAME"},
                      "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"1.0.1"}]}]}]
                    """.Replace("PACKAGE_NAME", name, StringComparison.Ordinal)
            };
            db.Rules.AddRange(excludedRule, alternateRule);
            db.Vulnerabilities.Add(advisory);
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = now
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = now.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = now.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = now.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = now.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = excludedRule.Id,
                VulnerabilityId = advisory.Id,
                Justification = "Exclude vulnerable versions"
            });
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        var url = "/SupplyChain/Index?tab=rules&catalogView=artifacts&query=" + Uri.EscapeDataString(name) +
            "&lookupName=" + Uri.EscapeDataString(name) + "&lookupVersion=1.0.0&lookupSource=" +
            Uri.EscapeDataString(source);
        using var response = await Http.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Pinned SHA-256", html);
        StringAssert.Contains(html, "Excluded vulnerable or uncertain version");
        StringAssert.Contains(html, "GHSA-excluded-test");
    }

    [TestMethod]
    public async Task ReviewQueueShowsAuthorizationScopeAndSeparatePolicyHolds()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var approvedName = "Example.ReviewScope." + Guid.NewGuid().ToString("N");
        var newName = "Example.ReviewChild." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var approved = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = approvedName,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = DateTime.UtcNow
            };
            // Even with a matching pinned rule, conflicting trusted bytes must be held.
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = approvedName,
                Version = "1.0.0",
                Source = source
            });
            var newArtifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = newName,
                Version = "1.0.0",
                Source = source
            };
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = approvedName,
                Version = "1.0.0",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.DependencyApplications.Add(new DependencyApplication
            {
                RequestedByUserId = "another-employee",
                Ecosystem = "nuget",
                Source = source,
                Status = ApplicationStatus.ReadyForReview,
                Justification = "Check the review scope",
                Packages =
                [
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = approved.Id, PackageVersion = approved, IsDirect = true },
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, PackageVersion = newArtifact }
                ]
            });
            await db.SaveChangesAsync();
        }
        await LoginAsAdmin();
        using var response = await Http.GetAsync("/DependencyReviews/Index?filter=pending");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Already approved");
        StringAssert.Contains(html, "Needs approval");
        Assert.DoesNotContain("Waiting for source verification", html);
        StringAssert.Contains(html, "Waiting for an up-to-date vulnerability check");
        StringAssert.Contains(html, newName);
        StringAssert.Contains(html, approvedName);
        Assert.IsFalse(html.Contains("name=\"supplierId\"", StringComparison.Ordinal));
        Assert.IsFalse(html.Contains("s360-concept-rail", StringComparison.Ordinal));

        var configuration = GetService<IConfiguration>();
        var originalSource = configuration["SupplyChain:NuGetSources:1"];
        configuration["SupplyChain:NuGetSources:1"] = "https://replacement.example.com/v3/index.json";
        try
        {
            using var removed = await Http.GetAsync("/DependencyReviews/Index?filter=pending");
            removed.EnsureSuccessStatusCode();
            var removedHtml = await removed.Content.ReadAsStringAsync();
            StringAssert.Contains(removedHtml, "This package source is no longer permitted");
            Assert.DoesNotContain("Package source could not be verified", removedHtml);
        }
        finally { configuration["SupplyChain:NuGetSources:1"] = originalSource; }
    }

    [TestMethod]
    public async Task ApprovalDoesNotAuthenticateOrRejectHistoricalArchiveHashes()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var name = "Example.VerifiedConflict." + Guid.NewGuid().ToString("N");
        var checkedAt = DateTime.UtcNow;
        string reportHash;
        int applicationId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = checkedAt
            };
            var application = new DependencyApplication
            {
                RequestedByUserId = "another-employee",
                Ecosystem = "nuget",
                Source = source,
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage(name, "1.0.0") }),
                Justification = "Review independently verified package bytes",
                ResolutionContext = "net10.0; any runtime",
                Status = ApplicationStatus.ReadyForReview,
                Packages = [new ApplicationPackage { ApplicationId = 0, PackageVersionId = artifact.Id, PackageVersion = artifact, IsDirect = true }]
            };

            db.DependencyApplications.Add(application);
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source
            });
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastAttemptAtUtc = checkedAt.AddSeconds(-1);
            audit.LastSuccessfulAttemptAtUtc = checkedAt.AddSeconds(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
            applicationId = application.Id;
            await db.SaveChangesAsync();
            reportHash = application.ReportHash = ReportFingerprint.ComputePersisted(application);
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        using var response = await PostForm("/DependencyReviews/Approve", new Dictionary<string, string>
        {
            ["id"] = applicationId.ToString(),
            ["reportHash"] = reportHash,
            ["expiresAtUtc"] = DateTime.UtcNow.AddDays(1).ToString("O"),
            ["reason"] = "Attempt to approve conflicting verified archives"
        }, tokenUrl: "/DependencyReviews/Index?filter=all");
        Assert.AreEqual(HttpStatusCode.Redirect, response.StatusCode);
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(ApplicationStatus.Approved,
            verifyDb.DependencyApplications.Single(a => a.Id == applicationId).Status);
        Assert.IsTrue(verifyDb.Rules.Where(r => r.Kind == RuleKind.Approval).Any(r => r.ApplicationId == applicationId));
    }

    [TestMethod]
    public async Task ApprovalRechecksNewBlockRevocationAndVersionExclusion()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var name = "Example.Review." + Guid.NewGuid().ToString("N");
        string reportHash;
        int applicationId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = DateTime.UtcNow
            };
            var application = new DependencyApplication
            {
                RequestedByUserId = "a-different-employee",
                Ecosystem = "nuget",
                Source = source,
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage(name, "1.0.0") }),
                Justification = "Test current review policy",
                ResolutionContext = "net10.0; any runtime",
                Status = ApplicationStatus.ReadyForReview,
                Packages = [new ApplicationPackage { ApplicationId = 0, PackageVersionId = artifact.Id, PackageVersion = artifact, IsDirect = true }]
            };

            db.DependencyApplications.Add(application);
            await db.SaveChangesAsync();
            applicationId = application.Id;
            await db.SaveChangesAsync();
            reportHash = application.ReportHash = ReportFingerprint.ComputePersisted(application);
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.Block,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "*",
                Status = RuleStatus.Approved,
                Justification = "Added after resolution"
            });
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        async Task<HttpResponseMessage> SubmitApproval() => await PostForm("/DependencyReviews/Approve",
            new Dictionary<string, string>
            {
                ["id"] = applicationId.ToString(),
                ["reportHash"] = reportHash,
                ["expiresAtUtc"] = DateTime.UtcNow.AddDays(1).ToString("O"),
                ["reason"] = "A reviewer tried to approve this dependency"
            }, tokenUrl: "/DependencyReviews/Index?filter=all");

        var configuration = GetService<IConfiguration>();
        var configuredSource = configuration["SupplyChain:NuGetSources:1"];
        configuration["SupplyChain:NuGetSources:1"] = "https://replacement.example.com/v3/index.json";
        try
        {
            using var removedSource = await SubmitApproval();
            Assert.AreEqual(HttpStatusCode.BadRequest, removedSource.StatusCode);
            StringAssert.Contains(await removedSource.Content.ReadAsStringAsync(),
                "source is no longer permitted");
        }
        finally
        {
            configuration["SupplyChain:NuGetSources:1"] = configuredSource;
        }

        using (var blocked = await SubmitApproval())
        {
            Assert.AreEqual(HttpStatusCode.BadRequest, blocked.StatusCode);
            var message = await blocked.Content.ReadAsStringAsync();
            StringAssert.Contains(message, name + " @ *");
            StringAssert.Contains(message, "Introduction path: " + name);
            StringAssert.Contains(message, "Added after resolution");
        }

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Where(r => r.Kind == RuleKind.Block).Single(b => b.PackagePattern == name).Status = RuleStatus.Revoked;
            db.DependencyApplications.Single(a => a.Id == applicationId).Status = ApplicationStatus.Revoked;
            db.Rules.AddRange(
                new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = applicationId,
                    Ecosystem = "nuget",
                    PackagePattern = name,
                    Version = "1.0.0",
                    Source = source,
                    Status = RuleStatus.Revoked
                },
                new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Ecosystem = "nuget",
                    PackagePattern = name,
                    Version = "1.0.0",
                    Source = source,
                    Status = RuleStatus.Revoked
                });
            await db.SaveChangesAsync();
        }

        using (var revoked = await SubmitApproval())
            Assert.AreEqual(HttpStatusCode.BadRequest, revoked.StatusCode);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var external = db.Rules.Where(r => r.Kind == RuleKind.Approval).Single(r => r.PackagePattern == name && r.ApplicationId == null);
            external.Status = RuleStatus.Approved;

            await db.SaveChangesAsync();
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var external = db.Rules.Where(r => r.Kind == RuleKind.Approval).Single(r => r.PackagePattern == name && r.ApplicationId == null);
            external.Version = "*";
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = external.Id,
                VulnerabilityId = 0,
                ParentRule = external,
                Vulnerability = new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = name,
                    SourceId = "GHSA-review-exclusion",
                    RawAffectedJson = $$"""
                        [{"package":{"ecosystem":"NuGet","name":"{{name}}"},"versions":["1.0.0"]}]
                        """
                },
                Justification = "Excluded from the existing approval"
            });
            var checkedAtUtc = DateTime.UtcNow;
            db.PackageVersions.Single(a => a.Name == name).LastCheckedAtUtc = checkedAtUtc;
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastAttemptAtUtc = checkedAtUtc.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = checkedAtUtc.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
        using (var excluded = await SubmitApproval())
        {
            Assert.AreEqual(HttpStatusCode.BadRequest, excluded.StatusCode);
            var message = await excluded.Content.ReadAsStringAsync();
            StringAssert.Contains(message, "Excluded from the existing approval");
            StringAssert.Contains(message, "Introduction path: " + name);
        }
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(ApplicationStatus.Revoked,
            verifyDb.DependencyApplications.Single(a => a.Id == applicationId).Status);
        Assert.AreEqual(1, verifyDb.Rules.Where(r => r.Kind == RuleKind.Approval).Count(r => r.PackagePattern == name &&
            r.Status == RuleStatus.Revoked));
    }

    [TestMethod]
    public async Task ApprovalHistoryKeepsReportAndGroupsEachDecisionBatch()
    {
        const string source = "https://api.nuget.org/v3/index.json";
        var suffix = Guid.NewGuid().ToString("N");
        string reportHash;
        int applicationId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var application = new DependencyApplication
            {
                RequestedByUserId = "another-employee",
                Ecosystem = "nuget",
                Source = source,
                DirectPackages = JsonSerializer.Serialize(new[] { new DirectPackage("Example.Batch.Root." + suffix, "1.0.0") }),
                Justification = "Review two resolved packages",
                ResolutionContext = "net10.0; any runtime",
                Status = ApplicationStatus.ReadyForReview,
                Packages = [
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, IsDirect = true, PackageVersion = new PackageVersion
                    {
                        Ecosystem = "nuget", Name = "Example.Batch.Root." + suffix,
                        Version = "1.0.0", Source = source, LastCheckedAtUtc = DateTime.UtcNow
                    } },
                    new ApplicationPackage { ApplicationId = 0, PackageVersionId = 0, PackageVersion = new PackageVersion
                    {
                        Ecosystem = "nuget", Name = "Example.Batch.Child." + suffix,
                        Version = "2.0.0", Source = source, LastCheckedAtUtc = DateTime.UtcNow
                    } }
                ]
            };

            db.DependencyApplications.Add(application);
            await db.SaveChangesAsync();
            applicationId = application.Id;

            await db.SaveChangesAsync();
            reportHash = application.ReportHash = ReportFingerprint.ComputePersisted(application);
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
                db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
                {
                    LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    LastSuccessAtUtc = DateTime.UtcNow
                });
            else
            {
                audit.LastAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-1);
                audit.LastSuccessAtUtc = DateTime.UtcNow;
            }
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        async Task<HttpResponseMessage> Approve(string hash) => await PostForm("/DependencyReviews/Approve",
            new Dictionary<string, string>
            {
                ["id"] = applicationId.ToString(),
                ["reportHash"] = hash,
                ["expiresAtUtc"] = DateTime.UtcNow.AddDays(30).ToString("O"),
                ["reason"] = "Reviewed the complete resolved package graph"
            }, tokenUrl: "/DependencyReviews/Index?filter=all");

        using (var changed = await Approve(new string('e', 64)))
            Assert.AreEqual(HttpStatusCode.BadRequest, changed.StatusCode);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var audit = await db.VulnerabilitySyncStates.SingleAsync();
            audit.LastSuccessfulAttemptAtUtc = audit.LastAttemptAtUtc;
            audit.LastSuccessAtUtc = audit.LastAttemptAtUtc!.Value.AddSeconds(1);
            audit.LastError = null;
            var application = await db.DependencyApplications.Include(a => a.Packages)
                .ThenInclude(p => p.PackageVersion).SingleAsync(a => a.Id == applicationId);
            foreach (var package in application.Packages)
                package.PackageVersion.LastCheckedAtUtc = audit.LastAttemptAtUtc.Value.AddTicks(1);
            await db.SaveChangesAsync();
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var audit = await db.VulnerabilitySyncStates.SingleAsync();
            audit.LastAttemptAtUtc = DateTime.UtcNow;
            audit.LastError = "OSV temporarily unavailable";
            await db.SaveChangesAsync();
        }
        using (var first = await Approve(reportHash))
            Assert.AreEqual(HttpStatusCode.Redirect, first.StatusCode,
                await first.Content.ReadAsStringAsync());
        using (var second = await Approve(reportHash))
            Assert.AreEqual(HttpStatusCode.Redirect, second.StatusCode);

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var application = db.DependencyApplications.Include(a => a.Packages).Single(a => a.Id == applicationId);
            var added = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = "Example.Batch.Added." + suffix,
                Version = "1.0.0",
                Source = source,
                LastCheckedAtUtc = DateTime.UtcNow
            };
            db.ApplicationPackages.Add(new ApplicationPackage { ApplicationId = application.Id, PackageVersionId = 0, PackageVersion = added });
            await db.SaveChangesAsync();
        }
        using (var changedGraph = await Approve(reportHash))
            Assert.AreEqual(HttpStatusCode.BadRequest, changedGraph.StatusCode);

        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var reviews = verifyDb.RuleChanges.Include(r => r.Rule)
            .Where(r => r.Rule.ApplicationId == applicationId).ToList();
        Assert.AreEqual(4, reviews.Count);
        Assert.IsTrue(reviews.All(r => r.ReportHash == reportHash));
        Assert.AreEqual(2, reviews.Select(r => r.DecisionBatchId).Distinct().Count());
        Assert.IsTrue(reviews.GroupBy(r => r.DecisionBatchId).All(group => group.Count() == 2));
        var renewedGrants = verifyDb.Rules.Where(r => r.Kind == RuleKind.Approval).Where(r => r.ApplicationId == applicationId).ToList();
        Assert.AreEqual(2, renewedGrants.Count);
    }

    [TestMethod]
    public async Task OnlyExplicitProductionBaselineChangesReportedImpact()
    {
        await LoginAsAdmin();
        var name = "Example.Impact." + Guid.NewGuid().ToString("N");
        var project = "impact-project-" + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        int vulnerableId;
        int fixedId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var vulnerable = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "8.0.1",
                Source = "https://nuget.aiursoft.com/v3/index.json"
            };
            var fixedArtifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "8.0.2",
                Source = vulnerable.Source
            };
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = name,
                SourceId = "GHSA-impact-" + Guid.NewGuid().ToString("N"),
                Summary = "Denial of service in the affected package",
                RawAffectedJson = $$"""
                    [{"package":{"ecosystem":"NuGet","name":"{{name}}"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"8.0.0"},{"fixed":"8.0.2"}]}]},
                     {"package":{"ecosystem":"NuGet","name":"Unrelated.Package"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"99.0.0"}]}]}]
                    """,
                Matches = [new VulnerabilityMatch { VulnerabilityId = 0, PackageVersionId = 0, PackageVersion = vulnerable }]
            });
            db.PackageVersions.Add(fixedArtifact);
            await db.SaveChangesAsync();
            vulnerableId = vulnerable.Id;
            fixedId = fixedArtifact.Id;
        }
        var baseline = new CheckContext { Purpose = "baseline", Provider = "local" };
        var review = new CheckContext
        {
            Purpose = "review",
            Provider = "gitlab",
            Ref = "master",
            DefaultBranch = "master",
            PipelineSource = "merge_request_event",
            MergeRequest = "42"
        };
        var baselineId = await Record(vulnerableId, baseline, -5, trusted: false);
        await Record(fixedId, review, -4, trusted: true);
        await Record(fixedId, new CheckContext(), -3, trusted: true);
        using (var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, name);
            StringAssert.Contains(html, "Production baseline reports an affected version");
            StringAssert.Contains(html, "Affected ranges and fix boundaries");
            StringAssert.Contains(html, "8.0.2");
            StringAssert.Contains(html, project);
            StringAssert.Contains(html, $"checkId={baselineId}");
            Assert.DoesNotContain("99.0.0", html);
        }
        using (var record = await Http.GetAsync($"/BuildChecks/Index?checkId={baselineId}"))
        {
            record.EnsureSuccessStatusCode();
            StringAssert.Contains(await record.Content.ReadAsStringAsync(), $"id=\"check-{baselineId}\"");
        }
        baseline.Provider = "gitlab";
        baseline.Ref = baseline.DefaultBranch = "master";
        baseline.PipelineSource = "schedule";
        await Record(fixedId, baseline, -2, trusted: true);
        await Record(vulnerableId, review, -1, trusted: false);
        using (var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            response.EnsureSuccessStatusCode();
            Assert.DoesNotContain(name, await response.Content.ReadAsStringAsync());
        }
        using (var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true"))
        {
            detailed.EnsureSuccessStatusCode();
            var html = await detailed.Content.ReadAsStringAsync();
            StringAssert.Contains(html, name);
            Assert.DoesNotContain("Review check history", html);
            Assert.DoesNotContain("MR !42", html);
        }
        await Record(vulnerableId, null, 0, trusted: false);
        using (var legacy = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            legacy.EnsureSuccessStatusCode();
            Assert.DoesNotContain(name, await legacy.Content.ReadAsStringAsync());
        }
        // Even an affected default-branch review cannot replace the production baseline.
        review.PipelineSource = "push";
        review.MergeRequest = null;
        await Record(vulnerableId, review, 1, trusted: false);
        using (var reviewOnly = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
            Assert.DoesNotContain(name, await reviewOnly.Content.ReadAsStringAsync());
        var affectedBaseline = await Record(vulnerableId, baseline, 2, trusted: false);
        using (var affected = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            var html = await affected.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "Production baseline reports an affected version");
            StringAssert.Contains(html, $"checkId={affectedBaseline}");
        }
        // An npm-only baseline cannot clear NuGet production usage.
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                BatchCount = 1,
                CreatedAtUtc = now.AddSeconds(3),
                ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Ecosystem = "npm" })
            });
            await db.SaveChangesAsync();
        }
        using (var otherScope = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
            StringAssert.Contains(await otherScope.Content.ReadAsStringAsync(), $"checkId={affectedBaseline}");
        // A newer incomplete baseline cannot replace the last complete inventory.
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                BatchCount = 2,
                CreatedAtUtc = now.AddSeconds(3),
                ContextJson = JsonSerializer.Serialize(baseline)
            });
            await db.SaveChangesAsync();
        }
        using (var incomplete = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
            StringAssert.Contains(await incomplete.Content.ReadAsStringAsync(), $"checkId={affectedBaseline}");
        // A full batch count with mixed graph availability is still incomplete.
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var runId = Guid.NewGuid().ToString("N");
            for (var index = 0; index < 2; index++)
                db.BuildChecks.Add(new BuildCheck
                {
                    Project = project,
                    RunId = runId,
                    BatchIndex = index,
                    BatchCount = 2,
                    ScannedProjectCount = 1,
                    CreatedAtUtc = now.AddSeconds(3),
                    ContextJson = JsonSerializer.Serialize(baseline),
                    GraphJson = index == 0 ? null : "[]"
                });
            await db.SaveChangesAsync();
        }
        using (var mixedGraphs = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            mixedGraphs.EnsureSuccessStatusCode();
            StringAssert.Contains(await mixedGraphs.Content.ReadAsStringAsync(), $"checkId={affectedBaseline}");
        }
        // A complete dependency-free production report clears the old inventory.
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                BatchCount = 1,
                CreatedAtUtc = now.AddSeconds(4),
                ContextJson = JsonSerializer.Serialize(baseline)
            });
            await db.SaveChangesAsync();
        }
        using (var cleared = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
            Assert.DoesNotContain(name, await cleared.Content.ReadAsStringAsync());

        async Task<int> Record(int artifactId, CheckContext? context, int seconds, bool trusted)
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = await db.PackageVersions.SingleAsync(a => a.Id == artifactId);
            var check = new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                ScannedProjectCount = 1,
                BatchCount = 1,
                CreatedAtUtc = now.AddSeconds(seconds),
                Trusted = trusted,
                ContextJson = context == null ? null : JsonSerializer.Serialize(context),
                Dependencies = [new BuildCheckDependency { BuildCheckId = 0, PackageVersionId = artifactId,
                    Ecosystem = artifact.Ecosystem, Name = artifact.Name, Version = artifact.Version,
                    Source = artifact.Source, Trusted = trusted }]
            };
            db.BuildChecks.Add(check);
            await db.SaveChangesAsync();
            return check.Id;
        }
    }

    [TestMethod]
    public async Task VulnerabilityProjectsIgnoreLegacyReviewsAndLinkOnlyBaselineOrUndeclaredReports()
    {
        await LoginAsAdmin();
        var suffix = Guid.NewGuid().ToString("N");
        var baselineProject = "company/baseline-" + suffix;
        var reviewProject = "company/review-" + suffix;
        var legacyProject = "company/legacy-" + suffix;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = "Example.ProjectImpact." + suffix,
                Version = "1.0.0",
                Source = "https://nuget.aiursoft.com/v3/index.json"
            };
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = artifact.Name,
                SourceId = "GHSA-projects-" + suffix,
                Matches = [new VulnerabilityMatch { VulnerabilityId = 0, PackageVersionId = 0, PackageVersion = artifact }]
            });
            var reports = new (string Project, string? Purpose, string? MergeRequest)[]
            {
                (baselineProject, "baseline", null),
                (baselineProject, "review", "1"),
                (reviewProject, "review", "2"),
                (reviewProject, "review", "3"),
                (legacyProject, null, null)
            };
            foreach (var report in reports)
                db.BuildChecks.Add(new BuildCheck
                {
                    Project = report.Project,
                    RunId = Guid.NewGuid().ToString("N"),
                    BatchCount = 1,
                    ScannedProjectCount = 1,
                    ContextJson = report.Purpose == null ? null : JsonSerializer.Serialize(new CheckContext
                    {
                        Purpose = report.Purpose,
                        Ecosystem = "nuget",
                        Provider = "gitlab",
                        Ref = "master",
                        DefaultBranch = "master",
                        PipelineSource = report.Purpose == "review" ? "merge_request_event" : "push",
                        MergeRequest = report.MergeRequest
                    }),
                    Dependencies = [new BuildCheckDependency
                    {
                        BuildCheckId = 0, PackageVersionId = 0, PackageVersion = artifact,
                        Ecosystem = "nuget", Name = artifact.Name, Version = artifact.Version,
                        Source = artifact.Source
                    }]
                });
            await db.SaveChangesAsync();
        }
        using var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Production baseline projects: <strong>1</strong>");
        Assert.DoesNotContain("Projects in review reports", html);
        StringAssert.Contains(html, "View reported projects");
        Assert.DoesNotContain(legacyProject, html);
        Assert.DoesNotContain(reviewProject, html);
        Assert.DoesNotContain("scope=review", html);
        var baselineLinks = System.Text.RegularExpressions.Regex.Matches(html, "href=\"([^\"]+)\"[^>]*>" + baselineProject + "</a>");
        Assert.AreEqual(1, baselineLinks.Count);
        var baselineUrl = WebUtility.HtmlDecode(baselineLinks[0].Groups[1].Value);
        StringAssert.Contains(baselineUrl, "scope=baseline");
        StringAssert.Contains(baselineUrl, "ecosystem=nuget");
        using (var projectPage = await Http.GetAsync(baselineUrl))
        {
            projectPage.EnsureSuccessStatusCode();
            StringAssert.Contains(await projectPage.Content.ReadAsStringAsync(), baselineProject);
        }
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        var detailedHtml = await detailed.Content.ReadAsStringAsync();
        Assert.DoesNotContain(reviewProject, detailedHtml);
        Assert.DoesNotContain("scope=review", detailedHtml);
        StringAssert.Contains(detailedHtml, legacyProject);
        StringAssert.Contains(detailedHtml, "scope=history");
    }

    [TestMethod]
    public async Task AuditOverviewDeduplicatesAcrossAllPagesAndCountsOnlyBaselineProjects()
    {
        await LoginAsAdmin();
        async Task<Dictionary<string, int>> Counts(string ecosystem)
        {
            using var response = await Http.GetAsync($"/VulnerabilityAudit/Index?ecosystem={ecosystem}");
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            return System.Text.RegularExpressions.Regex.Matches(html, """data-audit-count="([^"]+)">([0-9]+)</strong>""")
                .ToDictionary(m => m.Groups[1].Value, m => int.Parse(m.Groups[2].Value));
        }
        var before = await Counts("nuget");
        var npmBefore = await Counts("npm");
        int ruleId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var artifact = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = "Example.Overview",
                Version = "1.0.0",
                Source = "https://nuget.aiursoft.com/v3/index.json"
            };
            var rules = new[] { "1.*", "1.0.*" }.Select(version => new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = artifact.Name,
                Version = version,
                Source = artifact.Source,
                Status = RuleStatus.Approved
            }).ToList();
            db.Rules.AddRange(rules);
            for (var i = 0; i < 102; i++)
                db.Vulnerabilities.Add(new Vulnerability
                {
                    Ecosystem = "nuget",
                    PackageName = i == 101 ? "example.overview" : artifact.Name,
                    SourceId = $"GHSA-overview-{i}",
                    Aliases = i == 101 ? "[\"GHSA-overview-0\"]" : "[]",
                    RawAffectedJson = """
                        [{"package":{"ecosystem":"NuGet","name":"Example.Overview"},"versions":["1.0.0"]}]
                        """,
                    Matches = [new VulnerabilityMatch { VulnerabilityId = 0, PackageVersionId = 0, PackageVersion = artifact }]
                });
            foreach (var project in new[] { "company/one", "company/two", "company/review-only" })
                db.BuildChecks.Add(new BuildCheck
                {
                    Project = project,
                    RunId = Guid.NewGuid().ToString("N"),
                    BatchCount = 1,
                    ScannedProjectCount = 1,
                    ContextJson = JsonSerializer.Serialize(new CheckContext
                    {
                        Purpose = project.EndsWith("review-only", StringComparison.Ordinal) ? "review" : "baseline",
                        Ecosystem = "nuget"
                    }),
                    Dependencies = [new BuildCheckDependency
                    {
                        BuildCheckId = 0, PackageVersionId = 0, PackageVersion = artifact,
                        Ecosystem = "nuget", Name = artifact.Name, Version = artifact.Version,
                        Source = artifact.Source
                    }]
                });
            await db.SaveChangesAsync();
            ruleId = rules[0].Id;
        }
        foreach (var page in new[] { 1, 2 })
        {
            using var response = await Http.GetAsync($"/VulnerabilityAudit/Index?ecosystem=nuget&page={page}");
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, $"data-audit-count=\"advisories\">{before["advisories"] + 101}</strong>");
            StringAssert.Contains(html, $"data-audit-count=\"packages\">{before["packages"] + 1}</strong>");
            StringAssert.Contains(html, $"data-audit-count=\"projects\">{before["projects"] + 2}</strong>");
            StringAssert.Contains(html, $"data-audit-count=\"rules\">{before["rules"] + 2}</strong>");
            StringAssert.Contains(html, $"/SupplyChain/RuleDetails/{ruleId}");
            Assert.DoesNotContain("company/review-only", html);
        }
        var npmAfter = await Counts("npm");
        foreach (var count in npmBefore) Assert.AreEqual(count.Value, npmAfter[count.Key]);
    }

    [TestMethod]
    public async Task ImportedRuleDetailsShowHistoryExclusionsAndInactiveStatusWithoutWritingPolicy()
    {
        await LoginAsAdmin();
        int ruleId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var rule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = "Example.Details",
                Version = "1.*",
                Source = "https://nuget.aiursoft.com/v3/index.json",
                Justification = "Needed for document export",
                Status = RuleStatus.Revoked,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(-1),
                Reviews = [new RuleChange {  RuleId = 0, Decision = RuleStatus.Revoked,
                    ReviewerId = "reviewer", Reason = "Replaced by maintained package" }]
            };
            var advisory = new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = rule.PackagePattern,
                SourceId = "GHSA-rule-details",
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"Example.Details"},"versions":["1.0.0"]}]
                    """
            };
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = 0,
                ParentRule = rule,
                VulnerabilityId = 0,
                Vulnerability = advisory,
                Justification = "Exclude vulnerable old releases"
            });
            await db.SaveChangesAsync();
            ruleId = rule.Id;
        }
        await Http.GetAsync("/Account/LogOff");
        var account = await RegisterAndLoginAsync();
        using (var denied = await Http.GetAsync($"/SupplyChain/RuleDetails/{ruleId}"))
            AssertRedirect(denied, "/Error/Code403", exact: false);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Email == account.email);
            db.UserClaims.Add(new Microsoft.AspNetCore.Identity.IdentityUserClaim<string>
            {
                UserId = user.Id,
                ClaimType = Authorization.AppPermissions.Type,
                ClaimValue = Authorization.AppPermissionNames.CanReadSupplyChain
            });
            await db.SaveChangesAsync();
        }
        await Http.GetAsync("/Account/LogOff");
        await PostForm("/Account/Login", new Dictionary<string, string>
        { ["EmailOrUserName"] = account.email, ["Password"] = account.password });
        using var response = await Http.GetAsync($"/SupplyChain/RuleDetails/{ruleId}");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Needed for document export");
        StringAssert.Contains(html, "Replaced by maintained package");
        StringAssert.Contains(html, "Exclude vulnerable old releases");
        StringAssert.Contains(html, "GHSA-rule-details");
        StringAssert.Contains(html, "Expired");
        StringAssert.Contains(html, "Revoked");
        Assert.DoesNotContain("/SupplyChain/RevokeRule", html);
        Assert.DoesNotContain("/VulnerabilityAudit/ExcludeAffectedVersions", html);
        using var missing = await Http.GetAsync("/SupplyChain/RuleDetails/2147483647");
        Assert.AreEqual(HttpStatusCode.NotFound, missing.StatusCode);
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(RuleStatus.Revoked, (await verifyDb.Rules.Where(r => r.Kind == RuleKind.Approval).SingleOrDefaultAsync(r => r.Id == ruleId))!.Status);
        Assert.AreEqual(1, await verifyDb.RuleChanges.CountAsync(r => r.RuleId == ruleId));
        Assert.AreEqual(1, await verifyDb.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).CountAsync(e => e.ParentRuleId == ruleId));
    }

    [TestMethod]
    public async Task QuickAuditWarnsAboutUndownloadedVulnerableWildcardVersionUntilExcluded()
    {
        var packageName = "Example." + Guid.NewGuid().ToString("N");
        await LoginAsAdmin();
        int ruleId;
        int vulnerabilityId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var rule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var vulnerability = new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-" + Guid.NewGuid().ToString("N"),
                Summary = "Affected old version",
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                    """.Replace("PACKAGE", packageName, StringComparison.Ordinal)
            };
            db.Rules.Add(rule);
            db.Vulnerabilities.Add(vulnerability);
            await db.SaveChangesAsync();
            ruleId = rule.Id;
            vulnerabilityId = vulnerability.Id;
        }
        using (var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, packageName);
            StringAssert.Contains(html, "Current authorization range permits an affected version");
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = ruleId,
                VulnerabilityId = vulnerabilityId,
                Justification = "Affected versions excluded after review"
            });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            response.EnsureSuccessStatusCode();
            Assert.DoesNotContain(packageName, await response.Content.ReadAsStringAsync());
        }
        using (var response = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true"))
        {
            response.EnsureSuccessStatusCode();
            StringAssert.Contains(await response.Content.ReadAsStringAsync(), packageName);
        }
    }

    [TestMethod]
    public async Task QuickAuditDoesNotClaimOverlappingRulesAllowExcludedVersion()
    {
        var name = "Example.Overlap." + Guid.NewGuid().ToString("N");
        const string source = "https://api.nuget.org/v3/index.json";
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var broad = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "10.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            db.Rules.AddRange(broad, new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "10.0.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            }, new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "10.0.2",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            var advisory = new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = name,
                SourceId = "GHSA-overlap-" + Guid.NewGuid().ToString("N"),
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},
                      "ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.3"}]}]}]
                    """.Replace("PACKAGE", name, StringComparison.Ordinal)
            };
            db.Vulnerabilities.Add(advisory);
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = broad.Id,
                VulnerabilityId = advisory.Id,
                Justification = "Exclude the affected version across overlapping approvals"
            });
            await db.SaveChangesAsync();
        }

        using var quick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        quick.EnsureSuccessStatusCode();
        Assert.DoesNotContain(name, await quick.Content.ReadAsStringAsync());
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        StringAssert.Contains(await detailed.Content.ReadAsStringAsync(), name);
    }

    [TestMethod]
    public async Task QuickAuditHonorsNarrowExclusionWhenItCoversEntireAdvisory()
    {
        var name = "Example.NarrowExclusion." + Guid.NewGuid().ToString("N");
        const string source = "https://api.nuget.org/v3/index.json";
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "10.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            var narrow = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name,
                Version = "10.0.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var advisory = new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = name,
                SourceId = "GHSA-narrow-" + Guid.NewGuid().ToString("N"),
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},
                      "ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                    """.Replace("PACKAGE", name, StringComparison.Ordinal)
            };
            db.Rules.Add(narrow);
            db.Vulnerabilities.Add(advisory);
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                Kind = RuleKind.VulnerabilityExclusion,
                ParentRuleId = narrow.Id,
                VulnerabilityId = advisory.Id,
                Justification = "Exclude all affected versions without excluding the full major range"
            });
            await db.SaveChangesAsync();
        }

        using var quick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        quick.EnsureSuccessStatusCode();
        Assert.DoesNotContain(name, await quick.Content.ReadAsStringAsync());
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        StringAssert.Contains(await detailed.Content.ReadAsStringAsync(), name);
    }

    [TestMethod]
    public async Task QuickAuditAttributesCurrentUseToExactAuditedArtifact()
    {
        var name = "Example.ArtifactIdentity." + Guid.NewGuid().ToString("N");
        var project = "artifact-identity-" + Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        await LoginAsAdmin();
        int affectedId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var affected = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = "https://nuget.aiursoft.com/v3/index.json"
            };
            var otherSource = new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = "https://api.nuget.org/v3/index.json"
            };
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = name,
                SourceId = "GHSA-identity-" + Guid.NewGuid().ToString("N"),
                RawAffectedJson = "[]",
                Matches = [new VulnerabilityMatch { PackageVersionId = 0, VulnerabilityId = 0, PackageVersion = affected }]
            });
            db.PackageVersions.Add(otherSource);
            await db.SaveChangesAsync();
            affectedId = affected.Id;
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                BatchCount = 1,
                ScannedProjectCount = 1,
                CreatedAtUtc = now,
                Dependencies = [new BuildCheckDependency
                {
                    BuildCheckId = 0,
                    PackageVersionId = otherSource.Id, Ecosystem = "nuget", Name = name,
                    Version = "1.0.0", Source = otherSource.Source
                }]
            });
            await db.SaveChangesAsync();
        }

        using (var quick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            quick.EnsureSuccessStatusCode();
            Assert.DoesNotContain(name, await quick.Content.ReadAsStringAsync());
        }
        using (var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true"))
        {
            detailed.EnsureSuccessStatusCode();
            StringAssert.Contains(await detailed.Content.ReadAsStringAsync(), name);
        }

        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.BuildChecks.Add(new BuildCheck
            {
                Project = project,
                RunId = Guid.NewGuid().ToString("N"),
                BatchCount = 1,
                ScannedProjectCount = 1,
                CreatedAtUtc = now.AddSeconds(1),
                Dependencies = [new BuildCheckDependency
                {
                    BuildCheckId = 0,
                    PackageVersionId = affectedId, Ecosystem = "nuget", Name = name,
                    Version = "1.0.0", Source = "https://nuget.aiursoft.com/v3/index.json"
                }]
            });
            await db.SaveChangesAsync();
        }
        using var affectedQuick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        affectedQuick.EnsureSuccessStatusCode();
        var html = await affectedQuick.Content.ReadAsStringAsync();
        StringAssert.Contains(html, name);
        StringAssert.Contains(html, "Checks without a declared purpose");
    }

    [TestMethod]
    public async Task QuickAuditUsesEffectiveAuthorizationAfterAbsoluteVersionBlock()
    {
        var packageName = "Example.BlockedRange." + Guid.NewGuid().ToString("N");
        await LoginAsAdmin();
        int blockId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            var block = new PackageRule
            {
                Kind = RuleKind.Block,
                Status = RuleStatus.Approved,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.2",
                Justification = "Initially block only one affected version"
            };
            db.Rules.Add(block);
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-" + Guid.NewGuid().ToString("N"),
                Summary = "Affected versions remain in the allowed range",
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                    """.Replace("PACKAGE", packageName, StringComparison.Ordinal)
            });
            await db.SaveChangesAsync();
            blockId = block.Id;
        }
        using (var partial = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            partial.EnsureSuccessStatusCode();
            StringAssert.Contains(await partial.Content.ReadAsStringAsync(), packageName);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Where(r => r.Kind == RuleKind.Block).Single(b => b.Id == blockId).Version = "10.0.*";
            await db.SaveChangesAsync();
        }
        using (var covered = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            covered.EnsureSuccessStatusCode();
            Assert.DoesNotContain(packageName, await covered.Content.ReadAsStringAsync());
        }
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        StringAssert.Contains(await detailed.Content.ReadAsStringAsync(), packageName);
    }

    [TestMethod]
    public async Task QuickAuditDoesNotReportARevokedRangeAsCurrentlyAllowed()
    {
        var packageName = "Example.RevokedRange." + Guid.NewGuid().ToString("N");
        const string source = "https://api.nuget.org/v3/index.json";
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = source,
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-revoked-" + Guid.NewGuid().ToString("N"),
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},
                      "ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                    """.Replace("PACKAGE", packageName, StringComparison.Ordinal)
            });
            await db.SaveChangesAsync();
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = "https://nuget.aiursoft.com/v3/index.json",
                Status = RuleStatus.Revoked
            });
            await db.SaveChangesAsync();
        }
        using (var otherSource = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            otherSource.EnsureSuccessStatusCode();
            StringAssert.Contains(await otherSource.Content.ReadAsStringAsync(), packageName);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = source,
                Status = RuleStatus.Revoked
            });
            await db.SaveChangesAsync();
        }
        using var quick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget");
        quick.EnsureSuccessStatusCode();
        Assert.DoesNotContain(packageName, await quick.Content.ReadAsStringAsync());
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        StringAssert.Contains(await detailed.Content.ReadAsStringAsync(), packageName);
    }

    [TestMethod]
    public async Task WithdrawnAdvisoryRemainsHistoricalButIsNotCurrentRangeRisk()
    {
        await LoginAsAdmin();
        var packageName = "Example.Withdrawn." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            db.Rules.Add(new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = packageName,
                Version = "10.0.*",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.Vulnerabilities.Add(new Vulnerability
            {
                Ecosystem = "nuget",
                PackageName = packageName,
                SourceId = "GHSA-" + Guid.NewGuid().ToString("N"),
                Withdrawn = true,
                RawAffectedJson = """
                    [{"package":{"ecosystem":"NuGet","name":"PACKAGE"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
                    """.Replace("PACKAGE", packageName, StringComparison.Ordinal)
            });
            await db.SaveChangesAsync();
        }
        using (var quick = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget"))
        {
            quick.EnsureSuccessStatusCode();
            Assert.DoesNotContain(packageName, await quick.Content.ReadAsStringAsync());
        }
        using var detailed = await Http.GetAsync("/VulnerabilityAudit/Index?ecosystem=nuget&detailed=true");
        detailed.EnsureSuccessStatusCode();
        var html = await detailed.Content.ReadAsStringAsync();
        StringAssert.Contains(html, packageName);
        var findingStart = html.IndexOf($"<strong>{packageName}</strong>", StringComparison.Ordinal);
        var nextFinding = html.IndexOf("<div class=\"card mb-3\">", findingStart + 1, StringComparison.Ordinal);
        var findingHtml = nextFinding < 0 ? html[findingStart..] : html[findingStart..nextFinding];
        StringAssert.Contains(findingHtml, "Withdrawn");
        Assert.DoesNotContain("Current authorization range permits an affected version", findingHtml);
    }

    [TestMethod]
    public async Task ApprovalCenterSeparatesUpcomingAndExpiredReviews()
    {
        await LoginAsAdmin();
        var suffix = Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var userId = db.Users.First().Id;

            db.Rules.AddRange(
                new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Application = new DependencyApplication
                    {
                        RequestedByUserId = userId,
                        Ecosystem = "nuget",
                        Project = "upcoming-" + suffix,
                        Source = "https://api.nuget.org/v3/index.json",
                        Status = ApplicationStatus.Approved
                    },
                    Ecosystem = "nuget",
                    PackagePattern = "Example.Upcoming." + suffix,
                    Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json",
                    Status = RuleStatus.Approved,
                    ExpiresAtUtc = DateTime.UtcNow.AddDays(10)
                },
                new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Application = new DependencyApplication
                    {
                        RequestedByUserId = userId,
                        Ecosystem = "nuget",
                        Project = "expired-" + suffix,
                        Source = "https://api.nuget.org/v3/index.json",
                        Status = ApplicationStatus.Approved
                    },
                    Ecosystem = "nuget",
                    PackagePattern = "Example.Expired." + suffix,
                    Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json",
                    Status = RuleStatus.Approved,
                    ExpiresAtUtc = DateTime.UtcNow.AddDays(-1)
                });
            await db.SaveChangesAsync();
        }
        using (var response = await Http.GetAsync("/DependencyReviews/Index?filter=expiring"))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "upcoming-" + suffix);
            Assert.DoesNotContain("expired-" + suffix, html);
        }
        using (var response = await Http.GetAsync("/DependencyReviews/Index?filter=expired"))
        {
            response.EnsureSuccessStatusCode();
            var html = await response.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "expired-" + suffix);
            Assert.DoesNotContain("upcoming-" + suffix, html);
        }
    }

    [TestMethod]
    public async Task EditingAbsoluteBlockPreservesOldAndNewRuleWithReason()
    {
        await LoginAsAdmin();
        var oldName = "Example." + Guid.NewGuid().ToString("N");
        var newName = oldName + ".Renamed";
        int blockId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var block = new PackageRule
            {
                Kind = RuleKind.Block,
                Ecosystem = "nuget",
                PackagePattern = oldName,
                Version = "*",
                Status = RuleStatus.Approved,
                Justification = "Old security reason"
            };
            db.Rules.Add(block);
            await db.SaveChangesAsync();
            blockId = block.Id;
        }
        using var response = await PostForm("/SupplyChain/EditBlock", new Dictionary<string, string>
        {
            ["id"] = blockId.ToString(),
            ["packagePattern"] = newName,
            ["version"] = "2.*",
            ["reason"] = "Updated security reason",
            ["changeReason"] = "Upstream renamed the package"
        }, tokenUrl: "/SupplyChain/Index?tab=rules");
        Assert.AreEqual(HttpStatusCode.Redirect, response.StatusCode);
        using var verifyScope = Server!.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var changed = verifyDb.Rules.Where(r => r.Kind == RuleKind.Block).Single(b => b.Id == blockId);
        Assert.AreEqual(newName, changed.PackagePattern);
        Assert.AreEqual("2.*", changed.Version);
        var history = verifyDb.RuleChanges.Single(c => c.RuleId == blockId);
        StringAssert.Contains(history.Reason, oldName);
        StringAssert.Contains(history.Reason, newName);
        StringAssert.Contains(history.Reason, "Upstream renamed the package");
    }

    [TestMethod]
    public async Task RequestHistoryPaginationIncludesOlderRequestsAndOnlyTheOwner()
    {
        await LoginAsAdmin();
        int total;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var owner = await db.Users.SingleAsync(u => u.Email == "admin@default.com");
            total = await db.DependencyApplications.CountAsync(a => a.RequestedByUserId == owner.Id) + 101;
            var timestamp = DateTime.UtcNow;
            for (var i = 0; i < 101; i++)
                db.DependencyApplications.Add(new DependencyApplication
                {
                    RequestedByUserId = owner.Id,
                    Project = $"PaginationHistory-{i:000}",
                    Ecosystem = "nuget",
                    Source = "https://api.nuget.org/v3/index.json",
                    CreatedAtUtc = timestamp,
                    Status = ApplicationStatus.Failed
                });
            db.DependencyApplications.Add(new DependencyApplication
            {
                RequestedByUserId = "another-owner",
                Project = "PaginationHistory-Private",
                Ecosystem = "nuget",
                CreatedAtUtc = timestamp
            });
            await db.SaveChangesAsync();
        }
        var seen = new HashSet<string>();
        var pageCount = (total + 49) / 50;
        for (var page = 1; page <= pageCount; page++)
        {
            var html = await Http.GetStringAsync($"/DependencyRequests/History?page={page}");
            var rows = System.Text.RegularExpressions.Regex.Matches(html, @"<td>(PaginationHistory-\d+)</td>");
            Assert.IsTrue(rows.Count <= 50);
            foreach (System.Text.RegularExpressions.Match row in rows) Assert.IsTrue(seen.Add(row.Groups[1].Value));
            Assert.DoesNotContain("PaginationHistory-Private", html);
            StringAssert.Contains(WebUtility.HtmlDecode(html), $"{total} results · Page {page} of {pageCount}");
            if (page < pageCount) StringAssert.Contains(html, $"/DependencyRequests/History?page={page + 1}");
        }
        Assert.AreEqual(101, seen.Count);
        var last = await Http.GetStringAsync("/DependencyRequests/History?page=9999");
        StringAssert.Contains(WebUtility.HtmlDecode(last), $"{total} results · Page {pageCount} of {pageCount}");
        StringAssert.Contains(await Http.GetStringAsync("/DependencyRequests/Index?page=3"), "PaginationHistory-000");
        using var invalid = await Http.GetAsync("/DependencyRequests/History?page=0");
        Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [TestMethod]
    public async Task CatalogPaginationShowsOneListPerTabAndKeepsPagesAndFilters()
    {
        await LoginAsAdmin();
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();


            var now = DateTime.UtcNow;
            for (var i = 0; i < 501; i++)
            {
                var name = $"Pagination.Catalog{i:000}";
                db.Rules.Add(new PackageRule
                {
                    RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                    ApplicationId = null,
                    Ecosystem = "nuget",
                    PackagePattern = name,
                    Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json",
                    Status = RuleStatus.Approved
                });
                db.PackageVersions.Add(new PackageVersion
                {
                    Ecosystem = "nuget",
                    Name = name,
                    Version = "1.0.0",
                    Source = "https://api.nuget.org/v3/index.json",
                    LastCheckedAtUtc = now
                });
            }
            var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (audit == null)
            {
                audit = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(audit);
            }
            audit.LastAttemptAtUtc = now.AddMinutes(-1);
            audit.LastSuccessfulAttemptAtUtc = now.AddMinutes(-1);
            audit.LastSuccessAtUtc = DateTime.UtcNow;
            audit.LastError = null;
            await db.SaveChangesAsync();
        }
        var url = $"/SupplyChain/Index?tab=rules&ecosystem=nuget&query=Pagination.Catalog";
        static string TabUrl(string html, string title) => WebUtility.HtmlDecode(
            System.Text.RegularExpressions.Regex.Matches(html, @"<a\b[^>]*href=""([^""]+)""[^>]*>(.*?)</a>",
                    System.Text.RegularExpressions.RegexOptions.Singleline)
                .Single(m => m.Groups[2].Value.Contains(title, StringComparison.Ordinal)).Groups[1].Value);
        static void AssertOneList(string html, string selected, string other)
        {
            Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(html, "<table ").Count);
            Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(html, "aria-label=\"Result pages\"").Count);
            StringAssert.Contains(html, $"id=\"s360-catalog-{selected}\"");
            Assert.DoesNotContain($"id=\"s360-catalog-{other}\"", html);
            Assert.IsTrue(html.IndexOf("s360-inventory-tabs", StringComparison.Ordinal) < html.IndexOf("<table ", StringComparison.Ordinal));
            Assert.IsTrue(html.IndexOf("Result pages", StringComparison.Ordinal) > html.IndexOf("</table>", StringComparison.Ordinal));
        }
        var first = await Http.GetStringAsync(url);
        AssertOneList(first, "rules", "artifacts");
        Assert.AreEqual(50, System.Text.RegularExpressions.Regex.Matches(first, @"<code>Pagination.Catalog\d+</code>").Count);
        var last = await Http.GetStringAsync(url + "&page=11&artifactPage=11");
        AssertOneList(last, "rules", "artifacts");
        Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(last, @"<code>Pagination.Catalog500</code>").Count);
        StringAssert.Contains(WebUtility.HtmlDecode(last), "501 results · Page 11 of 11");
        var artifactUrl = TabUrl(last, "Reported versions");
        StringAssert.Contains(artifactUrl, "catalogView=artifacts");
        StringAssert.Contains(artifactUrl, "query=Pagination.Catalog");
        StringAssert.Contains(artifactUrl, "artifactPage=11");
        var artifacts = await Http.GetStringAsync(artifactUrl);
        AssertOneList(artifacts, "artifacts", "rules");
        Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(artifacts, @"<code>Pagination.Catalog500</code>").Count);
        StringAssert.Contains(artifacts, "name=\"catalogView\" value=\"artifacts\"");
        var back = await Http.GetStringAsync(TabUrl(artifacts, "Trust rules"));
        AssertOneList(back, "rules", "artifacts");
        StringAssert.Contains(WebUtility.HtmlDecode(back), "501 results · Page 11 of 11");
        var next = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(first,
            "href=\"([^\"]+#s360-catalog-rules)\">Next").Groups[1].Value);
        var nextHtml = await Http.GetStringAsync(next);
        StringAssert.Contains(nextHtml, "<code>Pagination.Catalog050</code>");
        Assert.DoesNotContain("<code>Pagination.Catalog000</code>", nextHtml);
        var artifactFirst = await Http.GetStringAsync(url + "&catalogView=artifacts");
        AssertOneList(artifactFirst, "artifacts", "rules");
        Assert.AreEqual(50, System.Text.RegularExpressions.Regex.Matches(artifactFirst, @"<code>Pagination.Catalog\d+</code>").Count);
        var artifactNext = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(artifactFirst,
            "href=\"([^\"]+#s360-catalog-artifacts)\">Next").Groups[1].Value);
        StringAssert.Contains(artifactNext, "catalogView=artifacts");
        StringAssert.Contains(await Http.GetStringAsync(artifactNext), "<code>Pagination.Catalog050</code>");
        var empty = await Http.GetStringAsync(url.Replace("query=Pagination.Catalog", "query=NoMatchingPaginationPackage", StringComparison.Ordinal) + "&catalogView=artifacts");
        StringAssert.Contains(WebUtility.HtmlDecode(empty), "0 results · Page 1 of 1");
        using var invalid = await Http.GetAsync(url + "&catalogView=invalid");
        Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [TestMethod]
    public async Task BlocklistPaginationReachesOldRulesAndRetainsEcosystem()
    {
        await LoginAsAdmin();
        int total;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            total = await db.Rules.Where(r => r.Kind == RuleKind.Block).CountAsync(b => b.Ecosystem == "npm") + 201;
            var now = DateTime.UtcNow;
            for (var i = 0; i < 201; i++)
                db.Rules.Add(new PackageRule
                {
                    Kind = RuleKind.Block,
                    Status = RuleStatus.Approved,
                    Ecosystem = "npm",
                    PackagePattern = $"pagination-block-{i:000}",
                    Justification = "Pagination regression",
                    RequestedAtUtc = now
                });
            db.Rules.Add(new PackageRule { Kind = RuleKind.Block, Status = RuleStatus.Approved, Ecosystem = "nuget", PackagePattern = "OtherEcosystem" });
            await db.SaveChangesAsync();
        }
        var first = await Http.GetStringAsync("/SupplyChain/Blocklist?ecosystem=npm");
        StringAssert.Contains(WebUtility.HtmlDecode(first), $"{total} results · Page 1 of {(total + 49) / 50}");
        StringAssert.Contains(first, "pagination-block-200");
        Assert.DoesNotContain("pagination-block-000", first);
        var next = WebUtility.HtmlDecode(System.Text.RegularExpressions.Regex.Match(first,
            "href=\"([^\"]+)\">Next").Groups[1].Value);
        StringAssert.Contains(next, "ecosystem=npm");
        var last = await Http.GetStringAsync("/SupplyChain/Blocklist?ecosystem=npm&page=5");
        StringAssert.Contains(last, "pagination-block-000");
        Assert.DoesNotContain("OtherEcosystem", last);
        using var invalid = await Http.GetAsync("/SupplyChain/Blocklist?page=-1");
        Assert.AreEqual(HttpStatusCode.BadRequest, invalid.StatusCode);
    }

    [TestMethod]
    public async Task BuildRecordPaginationPreservesExactCheckFilterWhenClampingPage()
    {
        await LoginAsAdmin();
        int checkId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var check = new BuildCheck { Project = "PaginationExact", RunId = Guid.NewGuid().ToString("N"), ScannedProjectCount = 1 };
            db.BuildChecks.Add(check);
            await db.SaveChangesAsync(); checkId = check.Id;
        }
        var html = await Http.GetStringAsync($"/BuildChecks/Index?checkId={checkId}&page=9999");
        StringAssert.Contains(html, "PaginationExact");
        StringAssert.Contains(WebUtility.HtmlDecode(html), "1 results · Page 1 of 1");
    }
    [TestMethod]
    public async Task ExactPackageApprovalRejectsPrefixesAndGroupsVersionGrants()
    {
        await LoginAsAdmin();
        var name = "Example.Policy." + Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();


            await db.SaveChangesAsync();
        }
        var fields = new Dictionary<string, string>
        {
            ["ecosystem"] = "nuget",
            ["packagePattern"] = name + ".*",
            ["version"] = "9.*",
            ["source"] = "https://api.nuget.org/v3/index.json",
            ["justification"] = "Approve one concrete dependency",
            ["expiresAtUtc"] = DateTime.UtcNow.AddDays(1).ToString("O")
        };
        using (var rejected = await PostForm("/SupplyChain/AddRule", fields, "/SupplyChain/Index?tab=rules"))
            Assert.AreEqual(HttpStatusCode.BadRequest, rejected.StatusCode);
        fields["packagePattern"] = name;
        using (var first = await PostForm("/SupplyChain/AddRule", fields, "/SupplyChain/Index?tab=rules"))
            Assert.AreEqual(HttpStatusCode.Redirect, first.StatusCode);
        fields["version"] = "10.*";
        fields["packagePattern"] = name.ToLowerInvariant();
        using (var second = await PostForm("/SupplyChain/AddRule", fields, "/SupplyChain/Index?tab=rules"))
            Assert.AreEqual(HttpStatusCode.Redirect, second.StatusCode);
        int policyId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var grants = await db.Rules.Where(r => r.Kind == RuleKind.Approval && r.PackagePattern.ToLower() == name.ToLower()).OrderBy(r => r.Id).ToListAsync();
            Assert.HasCount(2, grants);
            policyId = grants[0].Id;
        }
        var html = await Http.GetStringAsync("/SupplyChain/Index?tab=rules&query=" + name);
        Assert.AreEqual(1, System.Text.RegularExpressions.Regex.Matches(html, System.Text.RegularExpressions.Regex.Escape("/SupplyChain/PackageDetails?ruleId=" + policyId + "\"><code>")).Count);
        var details = await Http.GetStringAsync("/SupplyChain/PackageDetails?ruleId=" + policyId);
        StringAssert.Contains(details, "9.*");
        StringAssert.Contains(details, "10.*");
        using var prefixPreview = await Http.GetAsync("/SupplyChain/PreviewRule?ecosystem=nuget&packagePattern=" +
            Uri.EscapeDataString(name + ".*") + "&version=*&source=" + Uri.EscapeDataString(fields["source"]));
        Assert.AreEqual(HttpStatusCode.BadRequest, prefixPreview.StatusCode);
    }

    [TestMethod]
    public async Task LegacyMigrationRequiresHumanPermissionAndRejectsForgedNames()
    {
        await RegisterAndLoginAsync();
        using (var denied = await Http.GetAsync("/SupplyChain/MigrateLegacyRules"))
            Assert.AreNotEqual(HttpStatusCode.OK, denied.StatusCode);
        await LoginAsAdmin();
        var name = "Example.Migrate." + Guid.NewGuid().ToString("N");
        int originalId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();

            var rule = new PackageRule
            {
                RequestedAtUtc = DateTime.UtcNow.AddDays(-1),
                ApplicationId = null,
                Ecosystem = "nuget",
                PackagePattern = name + "*",
                Version = "1.*",
                Source = "https://api.nuget.org/v3/index.json",
                Status = RuleStatus.Approved
            };
            db.Rules.Add(rule);
            db.PackageVersions.Add(new PackageVersion
            {
                Ecosystem = "nuget",
                Name = name,
                Version = "1.0.0",
                Source = rule.Source
            });
            await db.SaveChangesAsync();
            originalId = rule.Id;
        }
        var page = await Http.GetStringAsync("/SupplyChain/MigrateLegacyRules");
        var fingerprint = System.Text.RegularExpressions.Regex.Match(page, "name=\"fingerprint\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.IsFalse(string.IsNullOrEmpty(fingerprint));
        Assert.DoesNotContain("checked=", page);
        var fields = new Dictionary<string, string>
        {
            ["fingerprint"] = fingerprint,
            ["selections"] = originalId + ":" + name + ".Fake",
            ["reason"] = "Review known concrete packages"
        };
        using (var forged = await PostForm("/SupplyChain/MigrateLegacyRules", fields))
            Assert.AreEqual(HttpStatusCode.BadRequest, forged.StatusCode);
        fields["selections"] = originalId + ":" + name;
        fields.Remove("__RequestVerificationToken");
        using (var csrf = await PostForm("/SupplyChain/MigrateLegacyRules", fields, includeToken: false))
            Assert.AreEqual(HttpStatusCode.BadRequest, csrf.StatusCode);
        using var migrated = await PostForm("/SupplyChain/MigrateLegacyRules", fields);
        Assert.AreEqual(HttpStatusCode.Redirect, migrated.StatusCode);
        using var verify = Server!.Services.CreateScope();
        var database = verify.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(1, await database.Rules.Where(r => r.Kind == RuleKind.Approval).CountAsync(r => r.LegacySourceRuleId == originalId));
        Assert.AreEqual(0, await database.Rules.Where(r => r.Kind == RuleKind.Approval).CountAsync(r => r.PackagePattern == name + ".Fake"));
    }

}
