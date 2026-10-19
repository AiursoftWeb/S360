using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.SupplyChainViewModels;

public class RuleDetailsViewModel : UiStackLayoutViewModel
{
    public RuleDetailsViewModel() => PageTitle = "Trust rule details";
    public required TrustRule Rule { get; init; }
    public List<TrustRuleVulnerabilityExclusion> Exclusions { get; init; } = [];
    public List<RuleAdvisoryRange> AdvisoryRanges { get; init; } = [];
}

public record RuleAdvisoryRange(Vulnerability Advisory, RangeRisk Intersection);
