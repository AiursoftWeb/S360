using Aiursoft.S360.Entities;
using Aiursoft.S360.Services;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public enum CatalogAuditStatus { Current, Failed, Missing, Stale }

public class CatalogViewModel : UiStackLayoutViewModel
{
    public CatalogViewModel() => PageTitle = "Dependency catalog";
    public InventoryViewModel? Inventory { get; set; }
    public string CatalogView { get; set; } = "rules";
    public string Ecosystem { get; set; } = "nuget";
    public string? Query { get; set; }
    public int? SupplierId { get; set; }
    public List<TrustRule> Rules { get; set; } = [];
    public Dictionary<int, string> BlockedRuleReasons { get; set; } = [];
    public List<CatalogArtifactRow> Artifacts { get; set; } = [];
    public List<Supplier> Suppliers { get; set; } = [];
    public int Page { get; set; } = 1;
    public int LegacyRuleCount { get; set; }
    public int TotalRules { get; set; }
    public int ArtifactPage { get; set; } = 1;
    public int TotalArtifacts { get; set; }
    public CatalogAuditStatus AuditStatus { get; set; }
    public bool LatestAuditFailed { get; set; }
    public string? LookupName { get; set; }
    public string? LookupVersion { get; set; }
    public string? LookupSource { get; set; }
    public string? LookupStatus { get; set; }
    public string? LookupReason { get; set; }
}

public record CatalogArtifactRow(PackageArtifact Artifact, TrustRule AuthorizingRule);

public class CatalogArtifactDetailsViewModel : UiStackLayoutViewModel
{
    public CatalogArtifactDetailsViewModel() => PageTitle = "Available dependency details";
    public required PackageArtifact Artifact { get; init; }
    public required TrustRule Rule { get; init; }
    public TrustRuleReview? LatestApproval { get; init; }
    public List<CatalogRelatedPackage> RecordedParents { get; init; } = [];
    public List<CatalogRelatedPackage> RecordedChildren { get; init; } = [];
    public bool ParentsLimited { get; init; }
    public bool ChildrenLimited { get; init; }
}

public record CatalogRelatedPackage(string Name, string Version, string Source);

public class RulePreviewViewModel : UiStackLayoutViewModel
{
    public RulePreviewViewModel() => PageTitle = "Preview trust rule";
    public string Ecosystem { get; set; } = "nuget";
    public string PackagePattern { get; set; } = "";
    public string Version { get; set; } = "";
    public string Source { get; set; } = "";
    public bool IncludePrerelease { get; set; }
    public List<RulePreviewMatch> Matches { get; set; } = [];
    public bool CandidateLimitReached { get; set; }
    public bool ResultLimitReached { get; set; }
}

public record RulePreviewMatch(string Name, string Version);

public class BlocklistViewModel : UiStackLayoutViewModel
{
    public BlocklistViewModel() => PageTitle = "Absolute blocklist";
    public string Ecosystem { get; set; } = "nuget";
    public List<BlockRule> Rules { get; set; } = [];
    public Dictionary<int, BlockRuleImpact> Impacts { get; set; } = [];
    public bool PreviewLimited { get; set; }
    public int Page { get; set; } = 1;
    public int Total { get; set; }
}

public record BlockRuleImpact(int ArtifactCount, int ApplicationCount, int CheckRunCount,
    List<string> ExamplePackages);

public class PackagePolicyViewModel : UiStackLayoutViewModel
{
    public PackagePolicyViewModel() => PageTitle = "Package authorization";
    public required PackagePolicy Policy { get; init; }
    public List<TrustRule> Grants { get; init; } = [];
    public int Page { get; init; } = 1;
    public int Total { get; init; }
    public List<string> RecordedProjects { get; init; } = [];
    public bool ProjectsLimited { get; init; }
}

public class LegacyMigrationViewModel : UiStackLayoutViewModel
{
    public LegacyMigrationViewModel() => PageTitle = "Review legacy package rules";
    public required LegacyMigrationPlan Plan { get; init; }
}
