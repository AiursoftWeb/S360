using System.CommandLine;
using System.Text.Json;
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
        Description = "Restored .sln file for NuGet/all checks; installed project directory for npm checks.",
        DefaultValueFactory = _ => "."
    };
    private static readonly Option<string?> ServerOption = new("--server")
    {
        Description = "S360 HTTPS address; defaults to S360_SERVER."
    };
    private static readonly Option<string> PurposeOption = new("--purpose")
    {
        Description = "review checks proposed dependencies; baseline declares these dependencies are in production and requires a baseline credential.",
        DefaultValueFactory = _ => "review"
    };
    private static readonly Option<string> EcosystemOption = new("--ecosystem")
    {
        Description = "Dependency ecosystem to check: all, nuget or npm.",
        DefaultValueFactory = _ => "all"
    };
    protected override IEnumerable<Option> GetCommandOptions() => [PathOption, ServerOption, PurposeOption, EcosystemOption];

    protected override async Task Execute(ParseResult context)
    {
        var purpose = context.GetValue(PurposeOption)!;
        if (purpose is not ("review" or "baseline"))
            throw new InvalidOperationException("--purpose must be review or baseline.");
        var ecosystem = context.GetValue(EcosystemOption)!;
        if (ecosystem is not ("all" or "nuget" or "npm"))
            throw new InvalidOperationException("--ecosystem must be all, nuget or npm.");
        var selectedEcosystem = ecosystem == "all" ? null : ecosystem;
        var server = context.GetValue(ServerOption) ?? Environment.GetEnvironmentVariable("S360_SERVER");
        var key = Environment.GetEnvironmentVariable("S360_CHECK_KEY");
        if (string.IsNullOrWhiteSpace(server))
            throw new InvalidOperationException("S360_SERVER must be configured.");
        if (purpose == "baseline" && string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("S360_CHECK_KEY is required for baseline reports.");
        var path = Path.GetFullPath(context.GetValue(PathOption)!);
        if (ecosystem != "npm" && !Path.GetExtension(path).Equals(".sln", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("NuGet checks require --path pointing to an explicit .sln file. Restore that same solution first.");
        // A lockfile URL must not silently redirect the archive download to another source.
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        http.Timeout = TimeSpan.FromMinutes(10);
        var scan = await DependencyScanner.ScanDetailedAsync(path, http, ecosystem: selectedEcosystem);
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
        var graphError = DependencyGraphNode.Validate(scan.GraphNodes, dependencies, selectedEcosystem, complete: true);
        if (graphError != null) throw new InvalidOperationException(graphError);
        var runId = Guid.NewGuid().ToString("N");
        var checkContext = ReadContext(Environment.GetEnvironmentVariable, purpose, selectedEcosystem);
        var requests = new List<CheckRequest>();
        var dependencyQueue = new Queue<Dependency>(dependencies);
        var graphQueue = new Queue<DependencyGraphNode>(scan.GraphNodes);
        // Bound serialized size, not just item count: shared transitive graphs can have many edges.
        do
        {
            var request = new CheckRequest
            {
                Context = checkContext, GraphNodes = [], ScannedProjectCount = scan.ScannedProjectCount,
                RunId = runId,
                Project = Environment.GetEnvironmentVariable("CI_PROJECT_PATH") ??
                    Path.GetFileName(ecosystem == "npm" ? path : Path.GetDirectoryName(path)!),
                Commit = Environment.GetEnvironmentVariable("CI_COMMIT_SHA"),
                Pipeline = Environment.GetEnvironmentVariable("CI_PIPELINE_URL")
            };
            var size = JsonSerializer.SerializeToUtf8Bytes(request).Length;
            while (dependencyQueue.TryPeek(out var dependency) && request.Dependencies.Count < 1000)
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(dependency).Length + 1;
                if (size + bytes > 3 * 1024 * 1024) break;
                request.Dependencies.Add(dependencyQueue.Dequeue());
                size += bytes;
            }
            while (graphQueue.TryPeek(out var node) && request.GraphNodes.Count < 1000)
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(node).Length + 1;
                if (size + bytes > 3 * 1024 * 1024) break;
                request.GraphNodes.Add(graphQueue.Dequeue());
                size += bytes;
            }
            if (request.Dependencies.Count == 0 && request.GraphNodes.Count == 0 &&
                (dependencyQueue.Count > 0 || graphQueue.Count > 0))
                throw new InvalidOperationException("A dependency graph node exceeds the report size limit.");
            requests.Add(request);
        } while (dependencyQueue.Count > 0 || graphQueue.Count > 0);
        if (requests.Count > 10000) throw new InvalidOperationException("The dependency report exceeds the batch limit.");
        for (var batchIndex = 0; batchIndex < requests.Count; batchIndex++)
        {
            var request = requests[batchIndex];
            request.BatchIndex = batchIndex;
            request.BatchCount = requests.Count;
            var batch = request.Dependencies;
            var response = await client.CheckAsync(server, key, request);
            if (response.Code != Code.ResultShown)
                throw new InvalidOperationException("S360 did not return a successful dependency-check result.");
            if (response.Decisions.Count != batch.Count)
                throw new InvalidOperationException("S360 returned an incomplete dependency decision set.");
            for (var i = 0; i < batch.Count; i++)
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

    public static CheckContext ReadContext(Func<string, string?> read, string purpose = "review", string? ecosystem = null) =>
        string.Equals(read("GITLAB_CI"), "true", StringComparison.OrdinalIgnoreCase)
            ? new CheckContext
            {
                Purpose = purpose, Ecosystem = ecosystem, Provider = "gitlab", PipelineSource = read("CI_PIPELINE_SOURCE"),
                Ref = read("CI_COMMIT_BRANCH") ?? read("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") ??
                    read("CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME") ?? read("CI_COMMIT_REF_NAME"),
                DefaultBranch = read("CI_DEFAULT_BRANCH"),
                MergeRequest = read("CI_MERGE_REQUEST_IID") ?? read("CI_EXTERNAL_PULL_REQUEST_IID"),
                Tag = read("CI_COMMIT_TAG")
            }
            : new CheckContext { Purpose = purpose, Ecosystem = ecosystem, Provider = "local" };
}
