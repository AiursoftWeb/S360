using System.CommandLine;
using System.Text.Json;
using Aiursoft.CommandFramework.Framework;
using Aiursoft.S360.SDK;
using Aiursoft.AiurProtocol.Services;
using Aiursoft.AiurProtocol;
using Microsoft.Extensions.DependencyInjection;

namespace Aiursoft.S360.Client;

public class CheckHandler : CommandHandlerBuilder
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
    public override Command BuildAsCommand()
    {
        var command = base.BuildAsCommand();
        foreach (var option in new Option[] { PathOption, ServerOption, PurposeOption, EcosystemOption })
            command.Options.Add(option);
        command.SetAction(Execute);
        return command;
    }

    private static async Task<int> Execute(ParseResult context)
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
        var denied = new List<DependencyDecision>();
        var reportErrors = new List<string>();
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
        // Review the complete scan before submitting any baseline batches. Polling
        // must never create duplicate or partially retried production reports.
        using var verificationDeadline = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        for (var index = 0; index < requests.Count; index++)
        {
            requests[index].BatchIndex = index;
            requests[index].BatchCount = requests.Count;
        }
        foreach (var request in requests)
        {
            request.Context = ReadContext(Environment.GetEnvironmentVariable, "review", selectedEcosystem);
            CheckResponse response;
            try
            {
                response = await client.CheckWhenReadyAsync(server, key, request,
                    TimeSpan.FromMinutes(10), verificationDeadline.Token);
            }
            catch (Exception ex) when (ex is TimeoutException ||
                                       ex is OperationCanceledException && verificationDeadline.IsCancellationRequested)
            {
                const string message = "S360 package verification did not complete within 10 minutes. " +
                    "The build remains blocked; check source verification and vulnerability audit job results, then retry.";
                if (purpose != "baseline")
                {
                    Console.Error.WriteLine(message);
                    Console.Error.WriteLine($"Audit status: {server.TrimEnd('/')}/VulnerabilityAudit/Index");
                    return 1;
                }
                Console.Error.WriteLine(message);
                // Still declare the complete production inventory, including rejected
                // packages; a failed preflight must not leave an old green baseline.
                break;
            }
            denied.AddRange(response.Decisions.Where(d => !d.Trusted));
            if (!response.Trusted && response.Decisions.All(d => d.Trusted))
                reportErrors.Add(response.Message ?? "S360 rejected the complete check without a package-specific reason.");
            approved &= response.Trusted && response.Decisions.All(d => d.Trusted);
        }
        if (purpose == "baseline")
        {
            approved = true;
            // Final baseline decisions can differ from preflight; display the
            // actual production report, without duplicate or stale denials.
            denied.Clear();
            reportErrors.Clear();
            foreach (var request in requests)
            {
                request.Context = checkContext;
                var response = await client.CheckAsync(server, key, request);
                approved &= response.Trusted && response.Decisions.All(d => d.Trusted);
                denied.AddRange(response.Decisions.Where(d => !d.Trusted));
                if (!response.Trusted && response.Decisions.All(d => d.Trusted))
                    reportErrors.Add(response.Message ?? "S360 rejected the complete check without a package-specific reason.");
            }
        }
        if (!approved)
        {
            WriteDenials(Console.Error, denied, scan, server, purpose, reportErrors);
            return 1;
        }
        Console.WriteLine($"S360 approved {dependencies.Count} dependency artifacts across {scan.ScannedProjectCount} supported projects.");
        return 0;
    }

    public static void WriteDenials(TextWriter output, IReadOnlyList<DependencyDecision> denied,
        ScanReport scan, string server, string purpose, IEnumerable<string> reportErrors)
    {
        var root = server.TrimEnd('/');
        output.WriteLine(denied.Count > 0
            ? $"S360 BLOCKED ({purpose}): {denied.Count} package artifact(s) need attention."
            : $"S360 BLOCKED ({purpose}): dependency report rejected.");
        for (var index = 0; index < denied.Count; index++)
        {
            var decision = denied[index];
            var package = decision.Dependency;
            output.WriteLine();
            output.WriteLine($"[{index + 1}] {package.Name}@{package.Version} ({package.Ecosystem})");
            output.WriteLine($"  Reason: {decision.Reason}");
            output.WriteLine($"  Source: {package.Source}");
            var paths = scan.PathsFor(package);
            if (paths.Count == 0)
                output.WriteLine("  Introduced by: unavailable in the restored dependency graph.");
            foreach (var path in paths)
            {
                var steps = path.Split(" → ");
                output.WriteLine($"  Project: {steps[0]}");
                foreach (var step in steps.Skip(1)) output.WriteLine($"    -> {step}");
            }
            var next = decision.PendingVerification
                ? $"Verification pending, not an approval request. Resolve other denials, then retry; if it persists, check {root}/VulnerabilityAudit/Index"
                : decision.Reason switch
                {
                    "No approved trust rule." => $"Request approval: {root}/DependencyRequests/Create",
                    "Approval expired; review required." => $"Request renewed approval: {root}/DependencyRequests/Create",
                    "This version has a known active vulnerability." => $"Upgrade or remove the affected dependency; inspect findings: {root}/VulnerabilityAudit/Index",
                    _ when decision.Reason.StartsWith("Excluded vulnerable or uncertain version:", StringComparison.Ordinal) =>
                        $"Use a version outside the excluded range; inspect findings: {root}/VulnerabilityAudit/Index",
                    _ => $"Review this policy/source/hash rejection with your security reviewer: {root}. An approval request does not bypass it."
                };
            output.WriteLine($"  Next: {next}");
        }
        foreach (var error in reportErrors)
        {
            output.WriteLine();
            output.WriteLine($"Report rejected: {error}");
            output.WriteLine("Next: Rerun the complete check; if it persists, contact the S360 administrator.");
        }
        if (denied.Any(d => !d.PendingVerification && d.Reason is "No approved trust rule." or "Approval expired; review required."))
        {
            output.WriteLine();
            output.WriteLine("For an approval request, enter the direct package you chose, with its exact version and source.");
            output.WriteLine("Follow the chain above to that direct package; S360 resolves the dependencies it brings in.");
        }
        output.WriteLine();
        output.WriteLine("The check failed. Build and publish must remain blocked until these issues are resolved.");
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
