using Aiursoft.S360.Services;

namespace Aiursoft.S360.Configuration;

public sealed class AlertCenterSettings
{
    public bool Enabled { get; init; }
    public bool AutoMitigate { get; init; }
    public string Endpoint { get; init; } = string.Empty;
    public string ApiKey { get; init; } = string.Empty;
    public string PublicBaseUrl { get; init; } = string.Empty;

    public void Validate()
    {
        foreach (var value in new[] { Endpoint, PublicBaseUrl })
            if (value.Length > 1000 || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
                throw new InvalidOperationException("AlertCenter integration requires HTTP(S) base URLs without credentials, query or fragment.");
        if (string.IsNullOrWhiteSpace(ApiKey)) throw new InvalidOperationException("An AlertCenter application API key is required.");
    }
}

public sealed class AlertCenterSettingsProvider(GlobalSettingsService settings)
{
    private Task<AlertCenterSettings>? _snapshot;
    public Task<AlertCenterSettings> GetAsync() => _snapshot ??= LoadAsync();

    private async Task<AlertCenterSettings> LoadAsync() => new()
    {
        Enabled = await settings.GetBoolSettingAsync(SettingsMap.AlertCenterEnabled),
        AutoMitigate = await settings.GetBoolSettingAsync(SettingsMap.AlertCenterAutoMitigate),
        Endpoint = await settings.GetSettingValueAsync(SettingsMap.AlertCenterEndpoint),
        ApiKey = await settings.GetSettingValueAsync(SettingsMap.AlertCenterApiKey),
        PublicBaseUrl = await settings.GetSettingValueAsync(SettingsMap.AlertCenterPublicBaseUrl)
    };
}
