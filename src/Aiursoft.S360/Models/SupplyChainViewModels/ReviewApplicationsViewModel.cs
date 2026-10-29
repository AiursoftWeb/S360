using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class ReviewApplicationsViewModel : UiStackLayoutViewModel
{
    public ReviewApplicationsViewModel() => PageTitle = "Dependency approvals";
    public List<DependencyApplication> Applications { get; set; } = [];
    public HashSet<int> ApplicationsWithRemovedSources { get; set; } = [];
    public Dictionary<int, List<ReviewPackageLine>> PackagesByApplicationId { get; set; } = [];
    public string Filter { get; set; } = "pending";
    public int Page { get; set; } = 1;
    public int Total { get; set; }
    public int PendingCount { get; set; }
    public int ExpiringCount { get; set; }
    public int ExpiredCount { get; set; }
}

public record ReviewPackageLine(PackageArtifact Artifact, bool IsDirect, bool AlreadyAuthorized,
    bool SourcePermitted, bool AuditCurrent, bool HasKnownVulnerability, bool CheckReady);
