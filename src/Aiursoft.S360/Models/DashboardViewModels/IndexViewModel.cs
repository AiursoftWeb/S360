using Aiursoft.UiStack.Layout;
using Aiursoft.S360.Entities;

namespace Aiursoft.S360.Models.DashboardViewModels;

public class IndexViewModel : UiStackLayoutViewModel
{
    public int MyRequests { get; set; }
    public int MyInProgress { get; set; }
    public int MyApproved { get; set; }
    public List<DependencyApplication> RecentRequests { get; set; } = [];
    public bool CanSubmitRequests { get; set; }
    public bool CanReadSupplyChain { get; set; }
    public bool CanReviewRequests { get; set; }
    public bool CanManageTrustRules { get; set; }
    public bool CanManageBlocklist { get; set; }
    public int PendingReviews { get; set; }
    public int TrackedArtifacts { get; set; }
    public int ActiveBlockRules { get; set; }
    public DateTime? LastVulnerabilitySyncUtc { get; set; }
    public SupplyChainViewModels.InventoryViewModel? Inventory { get; set; }

    public IndexViewModel()
    {
        PageTitle = "S360 overview";
    }
}
