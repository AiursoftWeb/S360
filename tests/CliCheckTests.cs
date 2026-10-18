using System.Diagnostics;
using System.Text.Json;
using Aiursoft.S360.Client;

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
        Assert.AreEqual("merge_request_event", context.PipelineSource);
        Assert.AreEqual("42", context.MergeRequest);
        Assert.AreEqual("refs/merge-requests/42/head", context.Ref);
        Assert.AreEqual("master", context.DefaultBranch);
        environment.Remove("GITLAB_CI");
        var local = CheckHandler.ReadContext(key => environment.GetValueOrDefault(key));
        Assert.AreEqual("local", local.Provider);
        Assert.IsNull(local.Ref);
        Assert.IsNull(local.MergeRequest);
    }

    [TestMethod]
    public async Task DependencyFreeProjectStillFailsWhenS360IsUnavailable()
    {
        var root = Path.Combine(Path.GetTempPath(), "s360-empty-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "obj"));
        try
        {
            var project = Path.Combine(root, "Empty.csproj");
            await File.WriteAllTextAsync(project, "<Project Sdk=\"Microsoft.NET.Sdk\" />");
            await File.WriteAllTextAsync(Path.Combine(root, "obj", "project.assets.json"),
                JsonSerializer.Serialize(new
                {
                    targets = new Dictionary<string, object> { ["net10.0"] = new { } },
                    packageFolders = new { }, libraries = new { },
                    project = new { restore = new { projectPath = project } }
                }));
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
                         "check", "--path", root, "--server", "http://127.0.0.1:1"
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
            StringAssert.Contains(output, "127.0.0.1");
            Assert.DoesNotContain("NuGet restore libraries are missing", output);
            Assert.DoesNotContain("S360 approved", output);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
