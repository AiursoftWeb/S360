using Aiursoft.Canon.BackgroundJobs;
using Aiursoft.S360.Services.AlertMonitoring;

namespace Aiursoft.S360.Services.BackgroundJobs;

public sealed class BaselineIncidentSyncJob(BaselineMonitoringService monitoring) : IBackgroundJob
{
    public string Name => "S360 security incident synchronization";
    public string Description => "Synchronizes confirmed company baseline security findings with AlertCenter independently of GitLab pipeline alerts.";
    public Task ExecuteAsync() => monitoring.SynchronizeAsync();
}
