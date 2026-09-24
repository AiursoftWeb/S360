using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class BuildChecksViewModel : UiStackLayoutViewModel
{
    public BuildChecksViewModel() => PageTitle = "Build check records";
    public string? Project { get; set; }
    public int Page { get; set; } = 1;
    public int Total { get; set; }
    public List<BuildCheck> Checks { get; set; } = [];
    public Dictionary<string, BuildRunStatus> RunStatuses { get; set; } = [];
    public Dictionary<int, string> CurrentBlockReasons { get; set; } = [];
}

public record BuildRunStatus(bool Complete, bool Trusted);
