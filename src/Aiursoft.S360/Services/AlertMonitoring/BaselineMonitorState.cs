using Aiursoft.S360.Models.SupplyChainViewModels;

namespace Aiursoft.S360.Services.AlertMonitoring;

public sealed record BaselineRepository(string Repository, InventoryStatus Status, bool CanMitigate,
    IReadOnlyList<InventoryProject> Projects, string FindingsJson);

public sealed record BaselineMonitorRun(DateTime CompletedAtUtc, bool Succeeded, IReadOnlyDictionary<string, Guid> Incidents);

public sealed class BaselineMonitorState
{
    public SemaphoreSlim Gate { get; } = new(1, 1);
    public BaselineMonitorRun? LastRun { get; set; }
}
