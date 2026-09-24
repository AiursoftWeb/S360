using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services;

public static class BlockRulePolicy
{
    public static BlockRule? Match(IEnumerable<BlockRule> rules, string ecosystem, string name, string version) =>
        rules.FirstOrDefault(rule => rule.Active && rule.Ecosystem == ecosystem &&
            TrustPattern.Matches(rule.PackagePattern, name, ecosystem) &&
            TrustPattern.VersionMatches(rule.Version, version, ecosystem, includePrerelease: true));

    public static string Explain(BlockRule rule, string name, string version, string? introductionPath = null) =>
        $"Absolutely blocked: {name}@{version} matches {rule.PackagePattern} @ {rule.Version}. " +
        $"Introduction path: {introductionPath ?? "not supplied"}. Reason: {rule.Reason}";
}
