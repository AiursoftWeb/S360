using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class RiskAcceptanceViewModel : UiStackLayoutViewModel
{
    public RiskAcceptanceViewModel() => PageTitle = "Vulnerability risk acceptance";
    public List<PackageRule> Rules { get; set; } = [];
    public Vulnerability? Advisory { get; set; }
    public List<string> Sources { get; set; } = [];
    public Dictionary<string, string> UserNames { get; set; } = [];
    public string Filter { get; set; } = "active";
    public int Page { get; set; } = 1;
    public int Total { get; set; }
}
