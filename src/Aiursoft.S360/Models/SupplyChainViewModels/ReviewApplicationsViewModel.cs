using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class ReviewApplicationsViewModel : UiStackLayoutViewModel
{
    public ReviewApplicationsViewModel() => PageTitle = "Dependency approvals";
    public List<DependencyApplication> Applications { get; set; } = [];
    public Dictionary<int, ReviewApplicationScope> ScopeByApplicationId { get; set; } = [];
    public HashSet<int> ApplicationsWithRemovedSources { get; set; } = [];
    public List<Supplier> Suppliers { get; set; } = [];
    public string Filter { get; set; } = "pending";
    public int Page { get; set; } = 1;
    public int Total { get; set; }
    public int PendingCount { get; set; }
    public int ExpiringCount { get; set; }
    public int ExpiredCount { get; set; }
}

public record ReviewApplicationScope(int Total, int AlreadyAuthorized, int CurrentlyClear, int SourceNotPermitted,
    List<string> NeedsReviewPreview, List<string> OnHoldPreview)
{
    public int NeedsReview => Total - AlreadyAuthorized - SourceNotPermitted;
    public int OnHold => AlreadyAuthorized - CurrentlyClear;
    public bool PreviewLimited => NeedsReview > NeedsReviewPreview.Count;
    public bool OnHoldPreviewLimited => OnHold > OnHoldPreview.Count;
}
