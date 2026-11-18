using System.Net;
using System.Text.Json.Serialization;

namespace Aiursoft.S360.Services.AlertMonitoring;

public enum BaselineLifecycleStatus
{
    Active,
    Unconfirmed,
    Retired
}

public interface IBaselineLifecycle
{
    Task<IReadOnlyDictionary<string, BaselineLifecycleStatus>> ReadAsync(IEnumerable<string> repositories);
}

public sealed class GitLabBaselineLifecycle(IHttpClientFactory clients, IConfiguration configuration, TimeProvider clock)
    : IBaselineLifecycle
{
    public const string ClientName = "GitLabBaselineLifecycle";
    private static readonly TimeSpan RefreshPeriod = TimeSpan.FromMinutes(5);
    private Dictionary<string, BaselineLifecycleStatus> _observations = new(StringComparer.Ordinal);
    private DateTimeOffset _nextRefresh;

    // Only the baseline synchronizer calls this method, under BaselineMonitorState.Gate.
    public async Task<IReadOnlyDictionary<string, BaselineLifecycleStatus>> ReadAsync(IEnumerable<string> repositories)
    {
        var paths = repositories.Distinct(StringComparer.Ordinal).ToArray();
        var endpoint = configuration["BaselineGitLab:Endpoint"];
        var token = configuration["BaselineGitLab:ReadToken"];
        if (paths.Length == 0 || (string.IsNullOrWhiteSpace(endpoint) && string.IsNullOrWhiteSpace(token)))
            return paths.ToDictionary(path => path, _ => BaselineLifecycleStatus.Active, StringComparer.Ordinal);

        if (clock.GetUtcNow() < _nextRefresh)
            return _observations.Count > 0 ? _observations :
                throw new InvalidOperationException("The GitLab project inventory is unavailable until the next refresh.");

        try
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var server) || server.Scheme != Uri.UriSchemeHttps ||
                server.AbsolutePath != "/" || server.UserInfo.Length != 0 || server.Query.Length != 0 ||
                server.Fragment.Length != 0 || string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException("GitLab baseline lifecycle requires an HTTPS origin and a read-only group token.");

            using var client = clients.CreateClient(ClientName);
            client.BaseAddress = new Uri(server, "api/v4/");
            client.DefaultRequestHeaders.Add("PRIVATE-TOKEN", token);
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var user = await ReadAsync<GitLabUser>(client, "user", budget.Token);
            var group = await ReadAsync<GitLabGroup>(client, "groups/aiursoft", budget.Token);
            if (user.Id <= 0 || group.Id <= 0 || group.FullPath != "aiursoft")
                throw new InvalidOperationException("The GitLab inventory identity or group could not be confirmed.");

            var membership = await ReadAsync<GitLabMembership>(client,
                FormattableString.Invariant($"groups/{group.Id}/members/all/{user.Id}"), budget.Token);
            if (membership.Id != user.Id || membership.AccessLevel < 20 || membership.State != "active")
                throw new InvalidOperationException("The GitLab inventory account must have active Reporter access to the company group.");

            var inventory = await ReadInventoryAsync(client, group.Id, budget.Token);
            var next = new Dictionary<string, BaselineLifecycleStatus>(StringComparer.Ordinal);
            foreach (var path in paths)
            {
                if (inventory.Contains(path) || await ProjectIsVisibleAsync(client, path, budget.Token))
                {
                    next.Add(path, BaselineLifecycleStatus.Active);
                    continue;
                }

                // A missing path cannot retire a baseline on its first observation.
                next.Add(path, _observations.GetValueOrDefault(path, BaselineLifecycleStatus.Active) == BaselineLifecycleStatus.Active
                    ? BaselineLifecycleStatus.Unconfirmed : BaselineLifecycleStatus.Retired);
            }
            _observations = next;
        }
        catch
        {
            // A failed or incomplete observation breaks the sequence of confirmations.
            _observations = new(StringComparer.Ordinal);
            throw;
        }
        finally
        {
            _nextRefresh = clock.GetUtcNow() + RefreshPeriod;
        }

        return _observations;
    }

    private static async Task<HashSet<string>> ReadInventoryAsync(HttpClient client, long groupId, CancellationToken cancellation)
    {
        var ids = new HashSet<long>();
        var inventory = new HashSet<string>(StringComparer.Ordinal);
        foreach (var archived in new[] { "false", "true" })
        {
            int? total = null;
            var count = 0;
            for (var page = 1; ; page++)
            {
                using var response = await client.GetAsync(FormattableString.Invariant(
                    $"groups/{groupId}/projects?include_subgroups=true&with_shared=false&archived={archived}&order_by=id&sort=asc&per_page=100&page={page}"), cancellation);
                response.EnsureSuccessStatusCode();
                var projects = await response.Content.ReadFromJsonAsync<GitLabProject[]>(cancellation)
                    ?? throw new InvalidOperationException("GitLab returned an empty inventory response.");
                if (!int.TryParse(Header(response, "X-Total"), out var expected) || expected < 0 ||
                    (total.HasValue && total.Value != expected) ||
                    Header(response, "X-Page") != page.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    throw new InvalidOperationException("GitLab inventory pagination could not be verified.");
                total = expected;
                foreach (var project in projects)
                {
                    if (project.Id <= 0 || project.PathWithNamespace is not { } path ||
                        !path.StartsWith("aiursoft/", StringComparison.Ordinal) || !ids.Add(project.Id) || !inventory.Add(path))
                        throw new InvalidOperationException("GitLab returned an inconsistent company project inventory.");
                }
                count += projects.Length;
                var next = Header(response, "X-Next-Page");
                if (count == total && next == "") break;
                if (projects.Length == 0 || count >= total ||
                    next != (page + 1).ToString(System.Globalization.CultureInfo.InvariantCulture))
                    throw new InvalidOperationException("GitLab returned an incomplete company project inventory.");
            }
        }
        if (inventory.Count == 0)
            throw new InvalidOperationException("An empty GitLab company inventory cannot establish project retirement.");
        return inventory;
    }

    private static string Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? values.Single() :
            throw new InvalidOperationException("A required GitLab pagination header is missing.");

    private static async Task<bool> ProjectIsVisibleAsync(HttpClient client, string path, CancellationToken cancellation)
    {
        using var response = await client.GetAsync("projects/" + Uri.EscapeDataString(path), cancellation);
        if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Found or
            HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
        {
            var location = response.Headers.Location;
            var server = client.BaseAddress!;
            if (location == null || !Uri.TryCreate(server, location, out var target) ||
                target.GetLeftPart(UriPartial.Authority) != server.GetLeftPart(UriPartial.Authority) ||
                target.UserInfo.Length != 0 || target.Query.Length != 0 || target.Fragment.Length != 0 ||
                !target.AbsolutePath.StartsWith("/api/v4/projects/", StringComparison.Ordinal) ||
                !long.TryParse(target.Segments[^1], out var projectId) || projectId <= 0 || target.Segments.Length != 5)
                throw new InvalidOperationException("GitLab redirected outside its project lookup API.");

            var redirected = await ReadAsync<GitLabProject>(client,
                FormattableString.Invariant($"projects/{projectId}"), cancellation);
            return redirected.Id == projectId && redirected.PathWithNamespace is not null
                ? true : throw new InvalidOperationException("The redirected GitLab project could not be confirmed.");
        }
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            // Distinguish a GitLab API response from an HTML proxy or ingress error page.
            var error = await response.Content.ReadFromJsonAsync<GitLabError>(cancellation);
            if (error?.Message == "404 Project Not Found") return false;
            throw new InvalidOperationException("GitLab did not confirm that the project path is missing.");
        }
        response.EnsureSuccessStatusCode();
        var project = await response.Content.ReadFromJsonAsync<GitLabProject>(cancellation);
        return project is { Id: > 0 } && project.PathWithNamespace is not null
            ? true // Existing projects, including archived projects, remain monitored.
            : throw new InvalidOperationException("GitLab could not confirm the project response.");
    }

    private static async Task<T> ReadAsync<T>(HttpClient client, string resource, CancellationToken cancellation)
        where T : class =>
        await client.GetFromJsonAsync<T>(resource, cancellation) ??
        throw new InvalidOperationException("GitLab returned an empty response.");

    private sealed record GitLabUser(long Id);
    private sealed record GitLabGroup(long Id, [property: JsonPropertyName("full_path")] string? FullPath);
    private sealed record GitLabMembership(long Id, [property: JsonPropertyName("access_level")] int AccessLevel, string? State);
    private sealed record GitLabProject(long Id, [property: JsonPropertyName("path_with_namespace")] string? PathWithNamespace);
    private sealed record GitLabError(string? Message);
}
