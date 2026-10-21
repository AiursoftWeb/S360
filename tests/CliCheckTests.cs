using System.Diagnostics;
using System.Text.Json;
using Aiursoft.S360.Client;
using Aiursoft.S360.SDK;
using Aiursoft.AiurProtocol;
using Aiursoft.AiurProtocol.Services;
using Aiursoft.AiurProtocol.Models;

namespace Aiursoft.S360.Tests;

[TestClass]
public class CliCheckTests
{
    [TestMethod]
    public async Task SolutionReportRejectsServerThatSilentlyIgnoresItsGraph()
    {
        var dependency = new Dependency { Ecosystem = "nuget", Name = "Example", Version = "1.0.0",
            Source = "https://api.nuget.org/v3/index.json", Sha256 = new string('a', 64) };
        var handler = new VerificationHandler(dependency, false);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAiurProtocolClient();
        services.AddHttpClient(string.Empty).ConfigurePrimaryHttpMessageHandler(() => handler);
        using var provider = services.BuildServiceProvider();
        var client = new S360Client(provider.GetRequiredService<AiurProtocolClient>());
        var request = new CheckRequest
        {
            ScannedProjectCount = 1, Dependencies = [dependency], BatchCount = 2,
            SolutionGraph = new SolutionDependencyGraph { SolutionPath = "App.sln" },
            Context = new CheckContext { Purpose = "review", Repository = "company/example", SolutionPath = "App.sln" }
        };
        var error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            client.CheckWhenReadyAsync("http://localhost", null, request, TimeSpan.FromSeconds(30)));
        StringAssert.Contains(error.Message, "Deploy the server update");
        Assert.IsFalse(client.SupportsSolutionGraphs);
        Assert.AreEqual(1, handler.Calls);
    }

#if DEBUG
    private const string BuildConfiguration = "Debug";
#else
    private const string BuildConfiguration = "Release";
#endif

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task PendingVerificationWaitsForAuditButPermanentDenialDoesNotRetry(bool pending)
    {
        var dependency = new Dependency { Ecosystem = "npm", Name = "sample", Version = "1.0.0",
            Source = "https://registry.npmjs.org", Sha256 = new string('a', 64) };
        var handler = new VerificationHandler(dependency, pending);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAiurProtocolClient();
        services.AddHttpClient(string.Empty).ConfigurePrimaryHttpMessageHandler(() => handler);
        using var provider = services.BuildServiceProvider();
        var client = new S360Client(provider.GetRequiredService<AiurProtocolClient>());
        var request = new CheckRequest { ScannedProjectCount = 1, Dependencies = [dependency] };
        var response = await client.CheckWhenReadyAsync("http://localhost", null, request, TimeSpan.FromSeconds(30));
        Assert.AreEqual(pending, response.Trusted);
        Assert.AreEqual(pending ? 2 : 1, handler.Calls);
    }

    [TestMethod]
    public async Task PendingVerificationTimesOutWithoutApprovingOrRetryingABaseline()
    {
        var dependency = new Dependency { Ecosystem = "npm", Name = "sample", Version = "1.0.0",
            Source = "https://registry.npmjs.org", Sha256 = new string('a', 64) };
        var handler = new VerificationHandler(dependency, true);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAiurProtocolClient();
        services.AddHttpClient(string.Empty).ConfigurePrimaryHttpMessageHandler(() => handler);
        using var provider = services.BuildServiceProvider();
        var client = new S360Client(provider.GetRequiredService<AiurProtocolClient>());
        var request = new CheckRequest { ScannedProjectCount = 1, Dependencies = [dependency] };
        await Assert.ThrowsAsync<TimeoutException>(() => client.CheckWhenReadyAsync("http://localhost", null,
            request, TimeSpan.FromSeconds(2)));
        Assert.AreEqual(1, handler.Calls);
        request.Context = new CheckContext { Purpose = "baseline" };
        await Assert.ThrowsAsync<ArgumentException>(() => client.CheckWhenReadyAsync("http://localhost", null,
            request, TimeSpan.FromSeconds(30)));
        Assert.AreEqual(1, handler.Calls);
    }

    [TestMethod]
    public void DenialsShowExactDependencyChainsAndApprovalEntryWithoutTreatingPendingAsUnapproved()
    {
        var missing = new Dependency { Ecosystem = "nuget", Name = "Microsoft.Bcl.AsyncInterfaces", Version = "9.0.4",
            Source = "https://nuget.example.test/v3/index.json", Sha256 = new string('a', 64) };
        var pending = new Dependency { Ecosystem = "nuget", Name = "Aiursoft.WebTools", Version = "10.0.19",
            Source = missing.Source, Sha256 = new string('b', 64) };
        var scan = new ScanReport([missing, pending], [], 2);
        scan.IntroductionPaths[DependencyIntroductionPaths.Identity(missing)] =
        [
            "src/App.csproj → Microsoft.ML@5.0.1 → Microsoft.Bcl.AsyncInterfaces@9.0.4",
            "tests/App.Tests.csproj → App (project reference) → Microsoft.ML@5.0.1 → Microsoft.Bcl.AsyncInterfaces@9.0.4"
        ];
        scan.IntroductionPaths[DependencyIntroductionPaths.Identity(pending)] =
            ["src/App.csproj → Aiursoft.WebTools@10.0.19"];
        using var output = new StringWriter();
        CheckHandler.WriteDenials(output,
            [new DependencyDecision { Dependency = missing, Reason = "No approved trust rule." },
                new DependencyDecision { Dependency = pending, PendingVerification = true,
                    Reason = "Package archive verification and vulnerability audit are pending." }],
            scan, "https://s360.example.test/prefix/", "review", []);
        var text = output.ToString();
        StringAssert.Contains(text, "S360 BLOCKED (review): 2 package artifact(s)");
        StringAssert.Contains(text, "[1] Microsoft.Bcl.AsyncInterfaces@9.0.4 (nuget)");
        StringAssert.Contains(text, missing.Source);
        StringAssert.Contains(text, "Project: src/App.csproj");
        StringAssert.Contains(text, "Project: tests/App.Tests.csproj");
        StringAssert.Contains(text, "-> Microsoft.ML@5.0.1");
        StringAssert.Contains(text, "-> App (project reference)");
        StringAssert.Contains(text, "-> Microsoft.Bcl.AsyncInterfaces@9.0.4");
        StringAssert.Contains(text, "Request approval: https://s360.example.test/prefix/DependencyRequests/Create");
        var pendingSection = text[text.IndexOf("[2]", StringComparison.Ordinal)..];
        StringAssert.Contains(pendingSection, "Verification pending, not an approval request");
        Assert.DoesNotContain("Request approval:", pendingSection);
        StringAssert.Contains(text, "direct package you chose");
    }

    [TestMethod]
    [DataRow("This version has a known active vulnerability.", "Upgrade or remove")]
    [DataRow("Excluded vulnerable or uncertain version: GHSA-example.", "outside the excluded range")]
    [DataRow("Previously recorded package bytes changed.", "policy/source/hash rejection")]
    [DataRow("Explicitly rejected or revoked.", "policy/source/hash rejection")]
    [DataRow("Package source is not permitted for S360 checks.", "policy/source/hash rejection")]
    public void SecurityDenialsDoNotSuggestRequestingApproval(string reason, string action)
    {
        var dependency = new Dependency { Ecosystem = "nuget", Name = "Example", Version = "1.2.3",
            Source = "https://nuget.example.test", Sha256 = new string('a', 64) };
        using var output = new StringWriter();
        CheckHandler.WriteDenials(output, [new DependencyDecision { Dependency = dependency, Reason = reason }],
            new ScanReport([dependency], [], 1), "https://s360.example.test", "baseline", []);
        var text = output.ToString();
        StringAssert.Contains(text, reason);
        StringAssert.Contains(text, action);
        StringAssert.Contains(text, "Introduced by: unavailable");
        Assert.DoesNotContain("Request approval:", text);
        Assert.DoesNotContain("/DependencyRequests/Create", text);
    }

    [TestMethod]
    public void RejectedReportIsNotPresentedAsSuccessfulPackagesOrAnApprovalRequest()
    {
        using var output = new StringWriter();
        CheckHandler.WriteDenials(output, [], new ScanReport([], [], 1),
            "https://s360.example.test", "baseline", ["The complete report is missing batches."]);
        var text = output.ToString();
        StringAssert.Contains(text, "S360 BLOCKED (baseline): dependency report rejected.");
        StringAssert.Contains(text, "Report rejected: The complete report is missing batches.");
        StringAssert.Contains(text, "Rerun the complete check");
        Assert.DoesNotContain("0 package", text);
        Assert.DoesNotContain("Request approval:", text);
    }

    private sealed class VerificationHandler(Dependency dependency, bool pending) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            var trusted = pending && Calls > 1;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(Newtonsoft.Json.JsonConvert.SerializeObject(new CheckResponse { Code = Code.ResultShown, Message = "Dependency review completed.", Trusted = trusted,
                    Decisions = [new DependencyDecision { Dependency = dependency, Trusted = trusted,
                        PendingVerification = pending && !trusted,
                        Reason = trusted ? "Approved" : pending ? "Audit pending" : "No approved trust rule." }] },
                    ProtocolSettings.JsonSettings), System.Text.Encoding.UTF8, "application/json")
            });
        }
    }

    [TestMethod]
    public void CliReportsGitlabContextWithoutPromotingLocalProjectVariables()
    {
        var environment = new Dictionary<string, string?>
        {
            ["GITLAB_CI"] = "true", ["CI_PIPELINE_SOURCE"] = "merge_request_event",
            ["CI_COMMIT_REF_NAME"] = "refs/merge-requests/42/head", ["CI_DEFAULT_BRANCH"] = "master",
            ["CI_MERGE_REQUEST_IID"] = "42"
        };
        var context = CheckHandler.ReadContext(key => environment.GetValueOrDefault(key));
        Assert.AreEqual("gitlab", context.Provider);
        Assert.AreEqual("review", context.Purpose);
        Assert.AreEqual("merge_request_event", context.PipelineSource);
        Assert.AreEqual("42", context.MergeRequest);
        Assert.AreEqual("refs/merge-requests/42/head", context.Ref);
        Assert.AreEqual("master", context.DefaultBranch);
        environment.Remove("GITLAB_CI");
        var local = CheckHandler.ReadContext(key => environment.GetValueOrDefault(key));
        Assert.AreEqual("local", local.Provider);
        Assert.AreEqual("review", local.Purpose);
        Assert.AreEqual("baseline", CheckHandler.ReadContext(key => environment.GetValueOrDefault(key), "baseline").Purpose);
        Assert.IsNull(local.Ref);
        Assert.IsNull(local.MergeRequest);
    }

    [TestMethod]
    [DataRow("nuget", true)]
    [DataRow("all", true)]
    [DataRow("nuget", false)]
    [DataRow("all", false)]
    public async Task CliRequiresSolutionAndStillFailsWhenS360IsUnavailable(string ecosystem, bool explicitSolution)
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-empty-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var project = Path.Combine(root, "Empty.csproj");
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>");
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { }, libraries = new { },
                    project = new { restore = new { projectPath = project } }
                }));
            var solution = await DependencyScannerTests.WriteSolutionAsync(root, project);
            var clientProject = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                "../../../../src/Aiursoft.S360.Client/Aiursoft.S360.Client.csproj"));
            var start = new ProcessStartInfo("dotnet")
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, WorkingDirectory = root
            };
            foreach (var argument in new[]
                     {
                         "run", "--no-build", "--no-restore", "--configuration", BuildConfiguration,
                         "--project", clientProject, "--",
                         "check", "--ecosystem", ecosystem, "--path", explicitSolution ? solution : root, "--server", "http://127.0.0.1:1"
                     }) start.ArgumentList.Add(argument);
            start.Environment["S360_CHECK_KEY"] = "test-only-check-key";
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the CLI.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                process.Kill(entireProcessTree: true);
                Assert.Fail("The S360 CLI did not exit after its server was unavailable.");
            }
            var output = await outputTask + await errorTask;
            Assert.AreNotEqual(0, process.ExitCode);
            StringAssert.Contains(output, explicitSolution ? "127.0.0.1" : "explicit .sln file");
            Assert.DoesNotContain("NuGet restore libraries are missing", output);
            Assert.DoesNotContain("S360 approved", output);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
