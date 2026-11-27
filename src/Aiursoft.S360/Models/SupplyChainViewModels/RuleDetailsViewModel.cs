using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class RuleDetailsViewModel : UiStackLayoutViewModel
{
    public RuleDetailsViewModel() => PageTitle = "Trust rule details";
    public required PackageRule Rule { get; init; }
    public List<PackageRule> Exclusions { get; init; } = [];
    public List<PackageRule> DerivedRules { get; init; } = [];
    public List<RuleAdvisoryRange> AdvisoryRanges { get; init; } = [];
    public PackageRelationshipViewModel? Relationship { get; init; }
    public RuleVersionSpectrumViewModel? Spectrum { get; init; }
}

public record RuleAdvisoryRange(Vulnerability Advisory, RangeRisk Intersection);
