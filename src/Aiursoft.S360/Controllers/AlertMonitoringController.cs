using Aiursoft.Canon.BackgroundJobs;
using Aiursoft.Canon.TaskQueue;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Configuration;
using Aiursoft.S360.Models.AlertMonitoring;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.AlertMonitoring;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.UiStack.Navigation;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Aiursoft.S360.Controllers;

[Authorize(Policy = AppPermissionNames.CanManageAlertCenterIntegration)]
[LimitPerMin]
public sealed class AlertMonitoringController(GlobalSettingsService settings, AlertCenterSettingsProvider settingsProvider,
    BaselineMonitoringService monitoring, BaselineMonitorState state, BackgroundJobRegistry jobs, ServiceTaskQueue queue,
    IStringLocalizer<AlertMonitoringController> localizer) : Controller
{
    [RenderInNavBar(NavGroupName = "Administration", NavGroupOrder = 9999, CascadedLinksGroupName = "Monitoring",
        CascadedLinksIcon = "bell", CascadedLinksOrder = 2, LinkText = "AlertCenter monitoring", LinkOrder = 1)]
    public async Task<IActionResult> Index()
    {
        var configuration = await settingsProvider.GetAsync();
        // Only validated URLs may become clickable links. Credentials never enter the view model.
        string? alertCenterUrl = null;
        if (Uri.TryCreate(configuration.Endpoint, UriKind.Absolute, out var endpoint) &&
            endpoint.Scheme is "http" or "https" && string.IsNullOrEmpty(endpoint.UserInfo) &&
            string.IsNullOrEmpty(endpoint.Query) && string.IsNullOrEmpty(endpoint.Fragment))
            alertCenterUrl = endpoint.AbsoluteUri.TrimEnd('/');
        return this.StackView(new MonitoringViewModel
        {
            Enabled = configuration.Enabled, ApiKeyConfigured = !string.IsNullOrWhiteSpace(configuration.ApiKey),
            AutoMitigate = configuration.AutoMitigate, RecoveryReadOnly = settings.IsOverriddenByConfig(SettingsMap.AlertCenterAutoMitigate),
            LastRun = state.LastRun, Repositories = await monitoring.PreviewAsync(), AlertCenterUrl = alertCenterUrl
        });
    }

    [HttpPost, ValidateAntiForgeryToken]
    public IActionResult Synchronize()
    {
        if (!queue.HasPendingOrProcessingTasks(nameof(BaselineIncidentSyncJob))) jobs.TriggerNow<BaselineIncidentSyncJob>();
        return RedirectToAction(nameof(Index));
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveRecovery(bool autoMitigate)
    {
        if (!ModelState.IsValid) return BadRequest();
        try { await settings.UpdateSettingAsync(SettingsMap.AlertCenterAutoMitigate, autoMitigate.ToString()); }
        catch (InvalidOperationException) { return Conflict(localizer["This setting is overridden by configuration."].Value); }
        return RedirectToAction(nameof(Index));
    }
}
