using System.CommandLine;
using Aiursoft.CommandFramework.Framework;
using Aiursoft.S360.SDK;
using Aiursoft.AiurProtocol.Services;
using Aiursoft.AiurProtocol;
using Aiursoft.AiurProtocol.Models;
using Microsoft.Extensions.DependencyInjection;

namespace Aiursoft.S360.Client;

public class CheckHandler : ExecutableCommandHandlerBuilder
{
    protected override string Name => "check";
    protected override string Description => "Reject unapproved NuGet and npm dependencies in the current build.";

    private static readonly Option<string> PathOption = new("--path", aliases: ["-p"])
    {
        Description = "Directory containing projects that have already been restored/installed.",
        DefaultValueFactory = _ => "."
    };
    private static readonly Option<string?> ServerOption = new("--server")
    {
        Description = "S360 HTTPS address; defaults to S360_SERVER."
    };
    protected override IEnumerable<Option> GetCommandOptions() => [PathOption, ServerOption];

    protected override async Task Execute(ParseResult context)
    {
        var server = context.GetValue(ServerOption) ?? Environment.GetEnvironmentVariable("S360_SERVER");
        var key = Environment.GetEnvironmentVariable("S360_CHECK_KEY");
        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("S360_SERVER and S360_CHECK_KEY must be configured.");
        var path = Path.GetFullPath(context.GetValue(PathOption)!);
        // A lockfile URL must not silently redirect the archive download to another source.
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        http.Timeout = TimeSpan.FromMinutes(10);
        var scan = await DependencyScanner.ScanDetailedAsync(path, http);
        var dependencies = scan.Dependencies;
        foreach (var skipped in scan.SkippedOptional)
            Console.WriteLine($"SKIPPED {skipped}");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAiurProtocolClient();
        // A custom CI credential must never be forwarded to another host by an HTTP redirect.
        services.AddHttpClient(string.Empty).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            AllowAutoRedirect = false
        });
        using var provider = services.BuildServiceProvider();
        var client = new S360Client(provider.GetRequiredService<AiurProtocolClient>());
        var approved = true;
        // The API limits request bodies to 4 MiB. A valid dependency can carry
        // long package and source names, so the model's 5000-item maximum is
        // not a safe wire-size target for large npm dependency graphs.
        var batches = dependencies.Count == 0 ? new List<Dependency[]> { Array.Empty<Dependency>() } : dependencies.Chunk(1000).ToList();
        var runId = Guid.NewGuid().ToString("N");
        for (var batchIndex = 0; batchIndex < batches.Count; batchIndex++)
        {
            var batch = batches[batchIndex];
            var response = await client.CheckAsync(server, key, new CheckRequest
            {
                Dependencies = batch.ToList(), ScannedProjectCount = scan.ScannedProjectCount,
                RunId = runId, BatchIndex = batchIndex, BatchCount = batches.Count,
                Project = Environment.GetEnvironmentVariable("CI_PROJECT_PATH") ?? Path.GetFileName(path),
                Commit = Environment.GetEnvironmentVariable("CI_COMMIT_SHA"),
                Pipeline = Environment.GetEnvironmentVariable("CI_PIPELINE_URL")
            });
            if (response.Code != Code.ResultShown)
                throw new InvalidOperationException("S360 did not return a successful dependency-check result.");
            if (response.Decisions.Count != batch.Length)
                throw new InvalidOperationException("S360 returned an incomplete dependency decision set.");
            for (var i = 0; i < batch.Length; i++)
            {
                var actual = response.Decisions[i].Dependency;
                var expected = batch[i];
                if (actual.Ecosystem != expected.Ecosystem || actual.Name != expected.Name ||
                    actual.Version != expected.Version || actual.Source != expected.Source ||
                    !actual.Sha256.Equals(expected.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("S360 returned a mismatched dependency decision set.");
            }
            foreach (var decision in response.Decisions.Where(d => !d.Trusted))
            {
                approved = false;
                Console.Error.WriteLine($"DENIED {decision.Dependency.Ecosystem} {decision.Dependency.Name}@{decision.Dependency.Version} from {decision.Dependency.Source}: {decision.Reason}");
                foreach (var introductionPath in scan.PathsFor(decision.Dependency))
                    Console.Error.WriteLine($"  Introduced by: {introductionPath}");
            }
            if (!response.Trusted && response.Decisions.All(d => d.Trusted))
                Console.Error.WriteLine($"DENIED: {response.Message} Rerun the full check.");
            approved &= response.Trusted;
        }
        if (!approved) throw new InvalidOperationException("S360 rejected dependencies. Submit a request through the S360 web UI.");
        Console.WriteLine($"S360 approved {dependencies.Count} dependency artifacts across {scan.ScannedProjectCount} supported projects.");
    }
}
