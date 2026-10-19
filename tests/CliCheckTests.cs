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
        using var handler = new VerificationHandler(dependency, pending);
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
        using var handler = new VerificationHandler(dependency, true);
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
