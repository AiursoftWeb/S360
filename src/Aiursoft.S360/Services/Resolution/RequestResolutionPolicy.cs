using Aiursoft.S360.Entities;

namespace Aiursoft.S360.Services.Resolution;

public static class RequestResolutionPolicy
{
    public static void ValidateBeforeDownload(string ecosystem, string source,
        IReadOnlyCollection<DirectPackage> direct, IConfiguration configuration,
        IReadOnlyCollection<BlockRule> blocks)
    {
        if (!AllowedPackageSources.Contains(configuration, ecosystem, source))
            throw new InvalidOperationException("Package source is no longer permitted for employee resolution.");
        if (direct.Count is < 1 or > 20)
            throw new InvalidOperationException("Request must have 1-20 direct packages.");
        foreach (var package in direct)
        {
            var block = BlockRulePolicy.Match(blocks, ecosystem, package.Name, package.Version);
            if (block != null)
                throw new InvalidOperationException(BlockRulePolicy.Explain(block,
                    package.Name, package.Version, package.Name));
        }
    }
}
