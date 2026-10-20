using System.Text.Json;

namespace Aiursoft.S360.SDK;

/// <summary>The observed structure in one report batch. NuGet has one solution; npm retains its manifests.</summary>
public class DependencyReportGraph
{
    public const int MaximumSerializedCharacters = 16 * 1024 * 1024;
    public SolutionDependencyGraph? Solution { get; set; }
    public List<DependencyGraphNode>? Manifests { get; set; }

    public static List<CheckRequest> CreateBatches(ScanReport scan, CheckContext context,
        string project, string? commit = null, string? pipeline = null)
    {
        var manifests = scan.GraphNodes.Where(n => scan.SolutionGraph == null || n.Ecosystem == "npm").ToList();
        var validation = Validate(new CheckRequest
        {
            Context = context, SolutionGraph = scan.SolutionGraph, GraphNodes = manifests,
            ScannedProjectCount = scan.ScannedProjectCount
        }, [], scan.Dependencies, true);
        if (validation != null) throw new InvalidOperationException(validation);
        var dependencies = new Queue<Dependency>(scan.Dependencies);
        var manifestNodes = new Queue<DependencyGraphNode>(manifests);
        var solutionNodes = new Queue<SolutionGraphNode>(scan.SolutionGraph?.Nodes ?? []);
        var contexts = new Queue<SolutionRestoreContext>();
        foreach (var restore in scan.SolutionGraph?.Contexts ?? [])
            foreach (var edges in restore.Edges.Chunk(1000).DefaultIfEmpty([]))
                contexts.Enqueue(new SolutionRestoreContext
                {
                    ProjectPath = restore.ProjectPath, Target = restore.Target,
                    ProjectTargets = restore.ProjectTargets, Edges = edges.ToList()
                });
        var runId = Guid.NewGuid().ToString("N");
        var requests = new List<CheckRequest>();
        do
        {
            var request = new CheckRequest
            {
                Context = context, Project = project, Commit = commit, Pipeline = pipeline,
                RunId = runId, ScannedProjectCount = scan.ScannedProjectCount, GraphNodes = [],
                SolutionGraph = scan.SolutionGraph == null ? null : new SolutionDependencyGraph
                    { SolutionPath = scan.SolutionGraph.SolutionPath }
            };
            var size = JsonSerializer.SerializeToUtf8Bytes(request).Length + 1024;
            void Fill<T>(Queue<T> queue, List<T> target)
            {
                while (queue.TryPeek(out var next) && target.Count < 1000)
                {
                    var bytes = JsonSerializer.SerializeToUtf8Bytes(next).Length + 1;
                    if (size + bytes > 3 * 1024 * 1024) break;
                    target.Add(queue.Dequeue());
                    size += bytes;
                }
            }
            Fill(dependencies, request.Dependencies);
            Fill(manifestNodes, request.GraphNodes);
            if (request.SolutionGraph != null)
            {
                Fill(solutionNodes, request.SolutionGraph.Nodes);
                Fill(contexts, request.SolutionGraph.Contexts);
            }
            var pending = dependencies.Count + manifestNodes.Count + solutionNodes.Count + contexts.Count;
            if (pending > 0 && request.Dependencies.Count + request.GraphNodes.Count +
                (request.SolutionGraph?.Nodes.Count ?? 0) + (request.SolutionGraph?.Contexts.Count ?? 0) == 0)
                throw new InvalidOperationException("A dependency graph item exceeds the report size limit.");
            requests.Add(request);
            if (requests.Count > 10000) throw new InvalidOperationException("The dependency report exceeds the batch limit.");
        } while (dependencies.Count + manifestNodes.Count + solutionNodes.Count + contexts.Count > 0);
        if (requests.Sum(r => (long)(Serialize(r)?.Length ?? 0)) > MaximumSerializedCharacters)
            throw new InvalidOperationException("The complete dependency graph exceeds the report size limit.");
        for (var i = 0; i < requests.Count; i++)
        {
            requests[i].BatchIndex = i;
            requests[i].BatchCount = requests.Count;
        }
        return requests;
    }

    public static DependencyReportGraph Read(string json) => json.AsSpan().TrimStart().StartsWith("[")
        ? new() { Manifests = JsonSerializer.Deserialize<List<DependencyGraphNode>>(json) }
        : JsonSerializer.Deserialize<DependencyReportGraph>(json) ?? throw new JsonException("Missing graph payload.");

    public static string? Serialize(CheckRequest request) => request.SolutionGraph != null
        ? JsonSerializer.Serialize(new DependencyReportGraph { Solution = request.SolutionGraph, Manifests = request.GraphNodes })
        : request.GraphNodes == null ? null : JsonSerializer.Serialize(request.GraphNodes);

    public static string? Validate(CheckRequest request, IReadOnlyCollection<DependencyReportGraph> earlier,
        IReadOnlyCollection<Dependency> dependencies, bool complete)
    {
        if (request.SolutionGraph == null)
        {
            if (request.GraphNodes == null) return null;
            var nodes = earlier.SelectMany(p => p.Manifests ?? []).Concat(request.GraphNodes).ToList();
            var error = DependencyGraphNode.Validate(nodes, dependencies, request.Context?.Ecosystem, complete);
            return error ?? (complete && nodes.Select(n => (n.Project, n.Ecosystem)).Distinct().Count() != request.ScannedProjectCount
                ? "Graph manifests must match the scanned project count." : null);
        }
        var partError = request.SolutionGraph.ValidatePart();
        if (partError != null) return partError;
        var manifests = request.GraphNodes ?? [];
        if (manifests.Any(n => n == null || n.Ecosystem != "npm"))
            return "NuGet relationships must be reported in the solution graph.";
        if (!complete) return DependencyGraphNode.Validate(manifests, [], "npm", false);
        if (earlier.Any(p => p.Solution == null)) return "The report changed graph formats between batches.";
        try
        {
            var graph = SolutionDependencyGraph.Assemble(earlier.Select(p => p.Solution!).Append(request.SolutionGraph).ToList());
            var allManifests = earlier.SelectMany(p => p.Manifests ?? []).Concat(manifests).ToList();
            var npmError = DependencyGraphNode.Validate(allManifests,
                dependencies.Where(d => d.Ecosystem == "npm").ToList(), "npm", true);
            return npmError ?? graph.Validate(dependencies,
                request.ScannedProjectCount - allManifests.Select(n => n.Project).Distinct().Count());
        }
        catch (ArgumentException ex) { return ex.Message; }
    }
}
