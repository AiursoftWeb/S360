using Aiursoft.AiurProtocol.Services;
using Aiursoft.AlertCenter.SDK;
using Aiursoft.AlertCenter.SDK.Models;
using Aiursoft.S360.Configuration;
using Microsoft.Extensions.Options;

namespace Aiursoft.S360.Services.AlertMonitoring;

public interface IBaselineIncidentClient
{
    Task<QueryIncidentsResponse> QueryAsync(QueryIncidentsRequest request);
    Task<CreateIncidentResponse> CreateAsync(CreateIncidentRequest request);
    Task<MitigateIncidentResponse> MitigateAsync(Guid id, MitigateIncidentRequest request);
    Task<PatchIncidentMetadataResponse> PatchAsync(Guid id, PatchIncidentMetadataRequest request);
}

public sealed class BaselineIncidentClient(AiurProtocolClient http, AlertCenterSettingsProvider settingsProvider) : IBaselineIncidentClient
{
    private Task<AlertCenterApiClient>? _client;
    private Task<AlertCenterApiClient> GetAsync() => _client ??= CreateAsync();

    private async Task<AlertCenterApiClient> CreateAsync()
    {
        var settings = await settingsProvider.GetAsync();
        settings.Validate();
        return new AlertCenterApiClient(http, Options.Create(new AlertCenterApiOptions { Endpoint = settings.Endpoint.TrimEnd('/') }),
            new SnapshotKeyProvider(settings.ApiKey));
    }

    public async Task<QueryIncidentsResponse> QueryAsync(QueryIncidentsRequest request) => await (await GetAsync()).QueryIncidentsAsync(request);
    public async Task<CreateIncidentResponse> CreateAsync(CreateIncidentRequest request) => await (await GetAsync()).CreateIncidentAsync(request);
    public async Task<MitigateIncidentResponse> MitigateAsync(Guid id, MitigateIncidentRequest request) => await (await GetAsync()).MitigateIncidentAsync(id, request);
    public async Task<PatchIncidentMetadataResponse> PatchAsync(Guid id, PatchIncidentMetadataRequest request) => await (await GetAsync()).PatchIncidentMetadataAsync(id, request);

    private sealed class SnapshotKeyProvider(string key) : IAlertCenterApiKeyProvider
    {
        public ValueTask<string> GetApiKeyAsync() => ValueTask.FromResult(key);
    }
}
