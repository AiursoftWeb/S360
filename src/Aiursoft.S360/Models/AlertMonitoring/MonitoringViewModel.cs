using Aiursoft.S360.Services.AlertMonitoring;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.AlertMonitoring;

public class MonitoringViewModel : UiStackLayoutViewModel
{
    public MonitoringViewModel() => PageTitle = "AlertCenter monitoring";
    public bool Enabled { get; init; }
    public bool ApiKeyConfigured { get; init; }
    public bool AutoMitigate { get; init; }
    public bool RecoveryReadOnly { get; init; }
    public BaselineMonitorRun? LastRun { get; init; }
    public IReadOnlyList<BaselineRepository> Repositories { get; init; } = [];
    public string? AlertCenterUrl { get; init; }
}
