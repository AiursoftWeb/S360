using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class MyRequestsViewModel : UiStackLayoutViewModel
{
    public MyRequestsViewModel() => PageTitle = "My dependency requests";
    public bool ShowCreateForm { get; set; } = true;
    public bool ShowHistory { get; set; } = true;
    public List<DependencyApplication> Applications { get; set; } = [];
    public Dictionary<int, string> CurrentBlockReasons { get; set; } = [];
    public HashSet<int> ApplicationsWithRemovedSources { get; set; } = [];
    public List<string> NuGetSources { get; set; } = [];
    public List<string> NpmSources { get; set; } = [];
}

public class RequestDetailsViewModel : UiStackLayoutViewModel
{
    public RequestDetailsViewModel() => PageTitle = "Dependency request";
    public DependencyApplication Application { get; set; } = new();
    public List<RequestPackageLine> Packages { get; set; } = [];
    public string? RetryDirectPackages { get; set; }
}

public class RequestPackageLine
{
    public required PackageArtifact Artifact { get; init; }
    public required string Path { get; init; }
    public bool IsDirect { get; init; }
    public bool SourcePermitted { get; init; }
    public bool AlreadyAuthorized { get; init; }
    public string AuthorizationReason { get; init; } = string.Empty;
    public bool CheckReady { get; init; }
    public string CheckReason { get; init; } = string.Empty;
}
