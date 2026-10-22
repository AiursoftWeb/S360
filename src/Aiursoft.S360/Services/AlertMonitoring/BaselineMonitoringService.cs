using System.Text.Json;
using Aiursoft.AlertCenter.SDK.Models;
using Aiursoft.S360.Configuration;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.Services.Vulnerability;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

namespace Aiursoft.S360.Services.AlertMonitoring;

public sealed class BaselineMonitoringService(TemplateDbContext db, CatalogInventoryService inventory,
    AlertCenterSettingsProvider settingsProvider, IBaselineIncidentClient client, BaselineMonitorState state,
    ILogger<BaselineMonitoringService> logger)
{
    public const string Source = "S360.ProductionBaseline";

    public Task<List<BaselineRepository>> PreviewAsync() => VulnerabilityAuditSnapshot.ExecuteAsync(db, async () =>
    {
        var projects = await inventory.ReadBaselineProjectsAsync();
        var audit = await db.VulnerabilitySyncStates.AsNoTracking().FirstOrDefaultAsync();
        var fresh = audit?.LastSuccessAtUtc > DateTime.UtcNow.AddHours(-12) &&
            !VulnerabilityAuditFreshness.HasFailedLatestAttempt(audit.LastAttemptAtUtc, audit.LastSuccessAtUtc, audit.LastError);
        return projects.GroupBy(p => p.Name.Split("//")[0], StringComparer.Ordinal)
            .Where(g => IsCompanyRepository(g.Key)).Select(g =>
            {
                var items = g.OrderBy(p => p.Name, StringComparer.Ordinal).ToList();
                var verdict = items.Max(p => p.Status);
                var findings = items.SelectMany(p => p.Versions.Where(v => v.Status == InventoryStatus.NonCompliant)
                        .Select(v => new { project = p.Name, package = v.Dependency.Name, version = v.Dependency.Version,
                            reason = v.Reason, advisories = v.Advisories }))
                    .OrderBy(f => f.project, StringComparer.Ordinal).ThenBy(f => f.package, StringComparer.Ordinal)
                    .ThenBy(f => f.version, StringComparer.Ordinal).ToList();
                // Bound remote metadata and descriptions without changing the assessment itself.
                var summary = JsonSerializer.Serialize(new { total = findings.Count, items = findings.Take(5).Select(f => new
                    { project = f.project[..Math.Min(f.project.Length, 160)], package = f.package[..Math.Min(f.package.Length, 160)],
                        version = f.version[..Math.Min(f.version.Length, 100)], reason = f.reason[..Math.Min(f.reason.Length, 200)],
                        advisories = f.advisories.Take(3).Select(a => a[..Math.Min(a.Length, 80)]) }),
                    reports = items.SelectMany(p => p.Reports).OrderBy(r => r.CheckId).Select(r => r.CheckId).Take(100) });
                return new BaselineRepository(g.Key, verdict, fresh && verdict == InventoryStatus.Compliant,
                    items, summary);
            }).OrderBy(p => p.Repository, StringComparer.Ordinal).ToList();
    });

    public static bool IsCompanyRepository(string repository) => repository.StartsWith("aiursoft/", StringComparison.Ordinal) &&
        repository.Length <= 240 && repository.Split('/').All(part => part.Length > 0 && part is not ("." or "..") &&
            part.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) && repository != "aiursoft/hom";

    public async Task SynchronizeAsync()
    {
        await state.Gate.WaitAsync();
        var links = new Dictionary<string, Guid>(StringComparer.Ordinal);
        try
        {
            var settings = await settingsProvider.GetAsync();
            if (!settings.Enabled) return;
            settings.Validate();
            var repositories = await PreviewAsync(); // Commit the database snapshot before any remote I/O.
            var active = await ReadActiveAsync();
            var owned = active.Where(i => i.Status == "new" && i.Metadata["source"] is JValue { Type: JTokenType.String } && i.Metadata.Value<string>("source") == Source &&
                    i.Metadata["repository"] is JValue { Type: JTokenType.String } && IsCompanyRepository(i.Metadata.Value<string>("repository")!))
                .GroupBy(i => i.Metadata.Value<string>("repository")!, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.OrderBy(i => i.ReceivedAtUtc).ThenBy(i => i.IncidentId).ToList(), StringComparer.Ordinal);
            var success = true;
            foreach (var repository in repositories)
            {
                try
                {
                    var incidents = owned.GetValueOrDefault(repository.Repository) ?? [];
                    if (repository.Status == InventoryStatus.NonCompliant)
                    {
                        if (incidents.Count == 0)
                        {
                            var created = await client.CreateAsync(new CreateIncidentRequest
                            {
                                ReportId = Guid.NewGuid(), Level = "sev2", OccurredAtUtc = DateTimeOffset.UtcNow,
                                Title = $"Security findings in {repository.Repository}"[..Math.Min(200, 21 + repository.Repository.Length)],
                                Content = Describe(repository, settings),
                                Context = new JObject { ["repository"] = repository.Repository, ["findings"] = JObject.Parse(repository.FindingsJson) },
                                Metadata = new JObject { ["source"] = Source, ["repository"] = repository.Repository,
                                    ["assessment"] = JObject.Parse(repository.FindingsJson) }
                            });
                            links[repository.Repository] = created.IncidentId;
                        }
                        else
                        {
                            links[repository.Repository] = incidents[0].IncidentId;
                            if (!JToken.DeepEquals(incidents[0].Metadata["assessment"], JObject.Parse(repository.FindingsJson)))
                                await client.PatchAsync(incidents[0].IncidentId, new PatchIncidentMetadataRequest
                                    { Version = incidents[0].Version, Property = "assessment", Value = JObject.Parse(repository.FindingsJson) });
                            // Preserve one unmitigated incident even when a previous ambiguous request created duplicates.
                            if (settings.AutoMitigate)
                                foreach (var duplicate in incidents.Skip(1))
                                    await client.MitigateAsync(duplicate.IncidentId, new MitigateIncidentRequest
                                        { Version = duplicate.Version, Reason = $"Duplicate of S360 incident {incidents[0].IncidentId}; the security findings remain active there." });
                        }
                    }
                    else if (repository.CanMitigate && settings.AutoMitigate)
                    {
                        foreach (var incident in incidents)
                        {
                            await client.MitigateAsync(incident.IncidentId, new MitigateIncidentRequest
                            {
                                Version = incident.Version,
                                Reason = $"S360 confirmed the complete production baseline for {repository.Repository} is compliant with current policy and vulnerability data. Baseline checks: {string.Join(", ", repository.Projects.SelectMany(p => p.Reports).Select(r => r.CheckId))}. This does not resolve any independent pipeline failure."
                            });
                            links[repository.Repository] = incident.IncidentId;
                        }
                    }
                    else if (incidents.Count > 0) links[repository.Repository] = incidents[0].IncidentId;
                }
                catch (Exception exception)
                {
                    success = false;
                    logger.LogError("Security incident synchronization failed for {Repository} with {ExceptionType}.", repository.Repository, exception.GetType().Name);
                }
            }
            state.LastRun = new BaselineMonitorRun(DateTime.UtcNow, success, links);
        }
        catch (Exception exception)
        {
            state.LastRun = new BaselineMonitorRun(DateTime.UtcNow, false, links);
            logger.LogError("Security incident synchronization failed with {ExceptionType}.", exception.GetType().Name);
        }
        finally { state.Gate.Release(); }
    }

    private async Task<List<IncidentDetails>> ReadActiveAsync()
    {
        var items = new List<IncidentDetails>();
        int? total = null;
        for (var page = 1; ; page++)
        {
            var response = await client.QueryAsync(new QueryIncidentsRequest
                { ActiveOnly = true, MetadataKey = "source", MetadataValue = Source, PageSize = 100, Page = page });
            total ??= response.TotalCount;
            if (response.Page != page || response.PageSize != 100 || total != response.TotalCount)
                throw new InvalidOperationException("The active incident listing changed; retry on the next synchronization.");
            items.AddRange(response.Items);
            if (items.Count >= total)
            {
                if (items.Count != total || items.Select(i => i.IncidentId).Distinct().Count() != items.Count)
                    throw new InvalidOperationException("The active incident listing is inconsistent.");
                return items;
            }
            if (response.Items.Count == 0) throw new InvalidOperationException("The incident listing ended early.");
        }
    }

    private static string Describe(BaselineRepository repository, AlertCenterSettings settings)
    {
        var details = string.Join('\n', repository.Projects.SelectMany(p => p.Versions.Where(v => v.Status == InventoryStatus.NonCompliant)
            .Select(v => $"{v.Dependency.Name}@{v.Dependency.Version}: {v.Reason}")));
        var reports = string.Join('\n', repository.Projects.SelectMany(p => p.Reports.Select(r =>
            $"{p.DisplayName}: commit {r.Commit ?? "unknown"}; pipeline {r.Pipeline ?? "unknown"}")));
        var link = settings.PublicBaseUrl.TrimEnd('/') + "/SupplyChain?tab=projects&scope=baseline&query=" + Uri.EscapeDataString(repository.Repository);
        var header = $"S360 found confirmed security or dependency-policy findings in the production dependency baseline for {repository.Repository}.\n\n";
        var footer = "\n\nNext steps: Upgrade the affected dependencies or correct the documented policy violation, then run the default-branch pipeline. " +
            "S360 automatically mitigates this incident when a complete production baseline is confirmed compliant with fresh vulnerability data, if automatic mitigation is enabled. " +
            "An MR review passing is not sufficient. A separate GitLab pipeline incident may share this cause; it recovers independently when the entire pipeline succeeds. " +
            "This baseline is a dependency observation, not proof of the version currently deployed. Final resolution remains manual.\n\nS360 details: " + link;
        var evidence = details[..Math.Min(details.Length, 1800)] + "\n\nBaseline evidence:\n" + reports[..Math.Min(reports.Length, 800)];
        var budget = 4000 - header.Length - footer.Length;
        return header + evidence[..Math.Min(evidence.Length, budget)] + footer;
    }
}
