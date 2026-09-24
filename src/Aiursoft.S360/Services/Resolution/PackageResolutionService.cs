using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public record DirectPackage(string Name, string Version);
public record ResolutionEdge(Dependency? Parent, Dependency Child);
public record ResolutionReport(List<Dependency> Dependencies, List<ResolutionEdge> Edges,
    List<string> SkippedOptional, string Context);

public class PackageResolutionService(IHttpClientFactory clients)
{
    public const string ArchiveClientName = "S360RegistryArchives";
    private const int MaxCapturedOutputChars = 4096;

    public async Task<ResolutionReport> ResolveAsync(string ecosystem, string source,
        IReadOnlyList<DirectPackage> direct, CancellationToken cancellationToken = default)
    {
        if (direct.Count is < 1 or > 20) throw new ArgumentException("Request must have 1-20 direct packages.");
        var operationId = Guid.NewGuid().ToString("N");
        var root = Path.Combine(Path.GetTempPath(), "s360-resolve-" + operationId);
        // Keep package caches outside the project tree. Packages can contain sample
        // .csproj/package.json files that must not be mistaken for review projects.
        var cacheRoot = Path.Combine(Path.GetTempPath(), "s360-cache-" + operationId);
        Directory.CreateDirectory(root);
        try
        {
            Directory.CreateDirectory(cacheRoot);
            if (ecosystem == "nuget")
            {
                var project = CreateNuGetProject(direct);
                project.Save(Path.Combine(root, "S360.Review.csproj"));
                CreateNuGetConfig(source).Save(Path.Combine(root, "NuGet.Config"));
                await RunAsync("dotnet", root, ["restore", "S360.Review.csproj", "--configfile", "NuGet.Config",
                    "--disable-parallel", "--no-http-cache"], cancellationToken,
                    new Dictionary<string, string>
                    {
                        ["NUGET_PACKAGES"] = Path.Combine(cacheRoot, "nuget")
                    });
            }
            else if (ecosystem == "npm")
            {
                var npmProject = new
                {
                    name = "s360-resolution-review", version = "1.0.0", @private = true,
                    dependencies = direct.ToDictionary(p => p.Name, p => p.Version, StringComparer.Ordinal)
                };
                await File.WriteAllTextAsync(Path.Combine(root, "package.json"),
                    JsonSerializer.Serialize(npmProject), cancellationToken);
                var cache = new Dictionary<string, string> { ["npm_config_cache"] = Path.Combine(cacheRoot, "npm") };
                await RunAsync("npm", root, ["install", "--package-lock-only", "--ignore-scripts",
                    "--no-audit", "--no-fund", "--registry", source], cancellationToken, cache);
                await DependencyScanner.ValidateNpmArchiveSourcesAsync(
                    Path.Combine(root, "package-lock.json"), source, cancellationToken);
                await RunAsync("npm", root, ["ci", "--ignore-scripts", "--no-audit", "--no-fund",
                    "--registry", source], cancellationToken, cache);
            }
            else throw new ArgumentOutOfRangeException(nameof(ecosystem));

            using var http = clients.CreateClient(ArchiveClientName);
            http.Timeout = TimeSpan.FromMinutes(5);
            var normalizedSource = TrustPattern.NormalizeSource(source);
            var scan = await DependencyScanner.ScanDetailedAsync(root, http, cancellationToken,
                expectedNpmSource: ecosystem == "npm" ? normalizedSource : null);
            if (scan.Dependencies.Any(d => d.Source != normalizedSource))
                throw new InvalidOperationException("Resolution used a package source outside the selected registry.");
            var edges = ecosystem == "nuget"
                ? ReadNuGetEdges(Path.Combine(root, "obj", "project.assets.json"), scan.Dependencies, direct)
                : ReadNpmEdges(Path.Combine(root, "package-lock.json"), scan.Dependencies, direct);
            ValidateGraph(scan.Dependencies, edges);
            var context = ecosystem == "nuget" ? "net10.0; any runtime" :
                $"npm; {RuntimeInformation.OSDescription}; {RuntimeInformation.ProcessArchitecture}";
            return new ResolutionReport(scan.Dependencies, edges, scan.SkippedOptional, context[..Math.Min(context.Length, 200)]);
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            finally
            {
                if (Directory.Exists(cacheRoot)) Directory.Delete(cacheRoot, recursive: true);
            }
        }
    }

    public static XDocument CreateNuGetProject(IReadOnlyList<DirectPackage> direct) =>
        new(new XElement("Project", new XAttribute("Sdk", "Microsoft.NET.Sdk"),
            // S360 audits vulnerabilities separately. Restore here must only resolve archives
            // from the selected source, not query an inherited NuGet audit source.
            new XElement("PropertyGroup", new XElement("TargetFramework", "net10.0"),
                new XElement("NuGetAudit", "false")),
            new XElement("ItemGroup", direct.Select(p => new XElement("PackageReference",
                new XAttribute("Include", p.Name), new XAttribute("Version", $"[{p.Version}]"))))));

    public static XDocument CreateNuGetConfig(string source) =>
        new(new XElement("configuration",
            new XElement("packageSources", new XElement("clear"),
                new XElement("add", new XAttribute("key", "S360 selected source"),
                    new XAttribute("value", TrustPattern.NormalizeSource(source))))));

    private static async Task RunAsync(string executable, string workDir, IReadOnlyList<string> args,
        CancellationToken cancellationToken, IReadOnlyDictionary<string, string> environment)
    {
        var start = new ProcessStartInfo(executable)
        {
            WorkingDirectory = workDir, UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true,
            CreateNoWindow = true
        };
        var inheritedPath = start.Environment.TryGetValue("PATH", out var pathValue) ? pathValue : null;
        start.Environment.Clear();
        if (inheritedPath != null) start.Environment["PATH"] = inheritedPath;
        // Never expose the service user's home (and its credentials) to package resolution.
        start.Environment["HOME"] = workDir;
        start.Environment["DOTNET_CLI_HOME"] = workDir;
        start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        // Keep the service's configured scratch volume when it differs from /tmp.
        // Clearing TMPDIR can make restore fail before it emits a useful error.
        var scratch = Environment.GetEnvironmentVariable("TMPDIR");
        if (!string.IsNullOrWhiteSpace(scratch)) start.Environment["TMPDIR"] = scratch;
        start.Environment["npm_config_userconfig"] = Path.Combine(workDir, "isolated.npmrc");
        foreach (var arg in args) start.ArgumentList.Add(arg);
        foreach (var item in environment) start.Environment[item.Key] = item.Value;
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {executable}.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(10));
        var outputTask = ReadBoundedOutputAsync(process.StandardOutput, deadline.Token);
        var errorTask = ReadBoundedOutputAsync(process.StandardError, deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            var error = await errorTask;
            var output = await outputTask;
            if (process.ExitCode != 0)
            {
                var detail = string.IsNullOrWhiteSpace(error) ? output : error;
                throw new InvalidOperationException($"{executable} dependency resolution failed " +
                    $"(exit code {process.ExitCode}): {detail[..Math.Min(detail.Length, 1500)]}");
            }
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{executable} dependency resolution timed out or was cancelled.");
        }
    }

    private static async Task<string> ReadBoundedOutputAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var captured = new StringBuilder(MaxCapturedOutputChars);
        var buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer, cancellationToken)) > 0)
        {
            // Keep the tail: restore/install errors are usually printed after progress logs.
            if (read >= MaxCapturedOutputChars)
            {
                captured.Clear();
                captured.Append(buffer, read - MaxCapturedOutputChars, MaxCapturedOutputChars);
            }
            else
            {
                var overflow = captured.Length + read - MaxCapturedOutputChars;
                if (overflow > 0) captured.Remove(0, overflow);
                captured.Append(buffer, 0, read);
            }
        }
        return captured.ToString();
    }

    public static List<ResolutionEdge> ReadNuGetEdges(string assetsPath, List<Dependency> dependencies,
        IReadOnlyList<DirectPackage> direct)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(assetsPath));
        var edges = new List<ResolutionEdge>();
        foreach (var target in doc.RootElement.GetProperty("targets").EnumerateObject())
        {
            var nodes = target.Value.EnumerateObject().Where(p => p.Value.GetProperty("type").GetString() == "package")
                .Select(p => (p.Name, Node: p.Value, Slash: p.Name.LastIndexOf('/')))
                .ToDictionary(p => p.Name[..p.Slash], p =>
                    dependencies.Single(d => d.Ecosystem == "nuget" &&
                        d.Name.Equals(p.Name[..p.Slash], StringComparison.OrdinalIgnoreCase) &&
                        d.Version == p.Name[(p.Slash + 1)..]), StringComparer.OrdinalIgnoreCase);
            foreach (var package in target.Value.EnumerateObject())
            {
                if (package.Value.GetProperty("type").GetString() != "package") continue;
                var parentName = package.Name[..package.Name.LastIndexOf('/')];
                var parent = nodes[parentName];
                if (!package.Value.TryGetProperty("dependencies", out var children)) continue;
                foreach (var child in children.EnumerateObject())
                    edges.Add(new ResolutionEdge(parent, nodes[child.Name]));
            }
            foreach (var root in direct)
            {
                if (!nodes.TryGetValue(root.Name, out var resolved) ||
                    !resolved.Version.Equals(root.Version, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"Direct NuGet dependency was not resolved at the requested version: {root.Name}@{root.Version}");
                edges.Add(new ResolutionEdge(null, resolved));
            }
        }
        return edges.DistinctBy(e => $"{e.Parent?.Name}\n{e.Parent?.Version}\n{e.Child.Name}\n{e.Child.Version}").ToList();
    }

    public static List<ResolutionEdge> ReadNpmEdges(string lockPath, List<Dependency> dependencies,
        IReadOnlyList<DirectPackage> direct)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(lockPath));
        var packages = doc.RootElement.GetProperty("packages");
        var installed = new Dictionary<string, Dependency>(StringComparer.Ordinal);
        foreach (var item in packages.EnumerateObject().Where(p => p.Name != ""))
        {
            var value = item.Value;
            var pathName = item.Name[(item.Name.LastIndexOf("node_modules/", StringComparison.Ordinal) + 13)..];
            var name = value.TryGetProperty("name", out var declared) ? declared.GetString()! : pathName;
            var version = value.GetProperty("version").GetString();
            var matching = dependencies.Where(d => d.Ecosystem == "npm" && d.Name == name && d.Version == version).ToList();
            if (matching.Count == 0 && value.TryGetProperty("optional", out var optional) && optional.GetBoolean()) continue;
            if (matching.Count != 1) throw new InvalidOperationException($"npm dependency identity is ambiguous: {item.Name}");
            installed[item.Name] = matching[0];
        }
        var edges = new List<ResolutionEdge>();
        foreach (var item in packages.EnumerateObject())
        {
            if (item.Name != "" && !installed.ContainsKey(item.Name)) continue;
            var parent = item.Name == "" ? null : installed[item.Name];
            var groups = item.Name == ""
                ? new[] { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" }
                : ["dependencies", "optionalDependencies", "peerDependencies"];
            foreach (var property in groups)
            {
                if (!item.Value.TryGetProperty(property, out var children) || children.ValueKind != JsonValueKind.Object) continue;
                foreach (var child in children.EnumerateObject())
                {
                    var path = ResolveInstalledPath(item.Name, child.Name, installed);
                    if (path == null)
                    {
                        if (property == "optionalDependencies") continue;
                        if (property == "peerDependencies" &&
                            item.Value.TryGetProperty("peerDependenciesMeta", out var peerMeta) &&
                            peerMeta.TryGetProperty(child.Name, out var peerInfo) &&
                            peerInfo.TryGetProperty("optional", out var peerOptional) && peerOptional.GetBoolean())
                            continue;
                        throw new InvalidOperationException($"npm dependency edge cannot be resolved: {item.Name} -> {child.Name}");
                    }
                    edges.Add(new ResolutionEdge(parent, installed[path]));
                }
            }
        }
        foreach (var root in direct)
            if (!edges.Any(e => e.Parent == null && e.Child.Name == root.Name && e.Child.Version == root.Version))
                throw new InvalidOperationException($"Direct npm dependency was not installed: {root.Name}@{root.Version}");
        return edges.DistinctBy(e => $"{e.Parent?.Name}\n{e.Parent?.Version}\n{e.Child.Name}\n{e.Child.Version}").ToList();
    }

    public static void ValidateGraph(IReadOnlyCollection<Dependency> dependencies,
        IReadOnlyCollection<ResolutionEdge> edges)
    {
        if (dependencies.Count == 0 || edges.Count == 0)
            throw new InvalidOperationException("The dependency resolution graph is empty.");
        var known = dependencies.Select(DependencyKey).ToHashSet(StringComparer.Ordinal);
        if (known.Count != dependencies.Count)
            throw new InvalidOperationException("The dependency resolution graph contains duplicate package identities.");
        if (dependencies.GroupBy(d => TrustService.Identity(d.Ecosystem, d.Name, d.Version, d.Source))
            .Any(group => group.Select(d => d.Sha256).Distinct(StringComparer.OrdinalIgnoreCase).Skip(1).Any()))
            throw new InvalidOperationException("The dependency resolution graph contains conflicting archive hashes for one package identity.");
        var children = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var queue = new Queue<string>();
        foreach (var edge in edges)
        {
            var child = DependencyKey(edge.Child);
            if (!known.Contains(child) || edge.Parent != null && !known.Contains(DependencyKey(edge.Parent)))
                throw new InvalidOperationException("The dependency resolution graph references a package outside the report.");
            if (edge.Parent == null)
            {
                queue.Enqueue(child);
                continue;
            }
            var parent = DependencyKey(edge.Parent);
            if (!children.TryGetValue(parent, out var siblings))
                children[parent] = siblings = [];
            siblings.Add(child);
        }
        var reachable = new HashSet<string>(StringComparer.Ordinal);
        while (queue.TryDequeue(out var key))
        {
            if (!reachable.Add(key)) continue;
            if (children.TryGetValue(key, out var next))
                foreach (var child in next) queue.Enqueue(child);
        }
        if (reachable.Count != known.Count)
            throw new InvalidOperationException("The dependency resolution graph contains packages with no introduction path from a direct dependency.");
    }

    private static string DependencyKey(Dependency dependency) =>
        $"{dependency.Ecosystem}\n{(dependency.Ecosystem == "nuget" ? dependency.Name.ToLowerInvariant() : dependency.Name)}\n" +
        $"{dependency.Version}\n{dependency.Source}\n{dependency.Sha256.ToLowerInvariant()}";

    private static string? ResolveInstalledPath(string parentPath, string name,
        IReadOnlyDictionary<string, Dependency> installed)
    {
        var prefix = parentPath;
        while (true)
        {
            var candidate = prefix.Length == 0 ? $"node_modules/{name}" : $"{prefix}/node_modules/{name}";
            if (installed.ContainsKey(candidate)) return candidate;
            var separator = prefix.LastIndexOf("/node_modules/", StringComparison.Ordinal);
            if (separator < 0)
            {
                if (prefix.Length == 0) return null;
                prefix = "";
            }
            else prefix = prefix[..separator];
        }
    }
}
