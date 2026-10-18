using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public enum InventoryStatus { Compliant, Pending, NonCompliant }

public class InventoryViewModel
{
    public const int PageSize = 20;
    public string Tab { get; init; } = "dependencies";
    public string Scope { get; init; } = "baseline";
    public string Ecosystem { get; init; } = "all";
    public string Filter { get; init; } = "all";
    public string? Query { get; init; }
    public string? Project { get; init; }
    public int Page { get; set; } = 1;
    public int Total { get; set; }
    public int PackageCount { get; set; }
    public int ProjectCount { get; set; }
    public int ProblemCount { get; set; }
    public bool CanRead { get; set; }
    public List<InventoryPackage> Packages { get; set; } = [];
    public List<InventoryProject> Projects { get; set; } = [];
    public int PageCount => Math.Max(1, (Total + PageSize - 1) / PageSize);
}

public class InventoryPackage
{
    public required string Name { get; init; }
    public required string Ecosystem { get; init; }
    public required string Source { get; init; }
    public List<InventoryVersion> Versions { get; init; } = [];
    public InventoryStatus Status => Versions.Max(v => v.Status);
    public List<string> Projects => Versions.SelectMany(v => v.Uses).Select(u => u.Project).Distinct().Order().ToList();
}

public class InventoryVersion
{
    public required Dependency Dependency { get; init; }
    public InventoryStatus Status { get; init; }
    public required string Reason { get; init; }
    public List<string> Advisories { get; init; } = [];
    public List<TrustRule> Rules { get; init; } = [];
    public List<DependencyApplication> Requests { get; init; } = [];
    public List<InventoryUse> Uses { get; init; } = [];
}

public record InventoryUse(string Project, int CheckId, DateTime CheckedAtUtc, string? Commit, string? Pipeline);

public class InventoryProject
{
    public required string Name { get; init; }
    public List<InventoryVersion> Versions { get; init; } = [];
    public List<InventoryReport> Reports { get; init; } = [];
    public bool Incomplete { get; set; }
    public InventoryStatus Status => Versions.Any(v => v.Status == InventoryStatus.NonCompliant)
        ? InventoryStatus.NonCompliant
        : Incomplete || Reports.Select(r => r.Ecosystem).Distinct().Count() < 2 ||
          Versions.Any(v => v.Status == InventoryStatus.Pending)
            ? InventoryStatus.Pending : InventoryStatus.Compliant;
}

public record InventoryReport(string Ecosystem, int CheckId, DateTime CheckedAtUtc, string? Commit, string? Pipeline);
