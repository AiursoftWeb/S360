using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public static class AllowedPackageSources
{
    public static bool Contains(IConfiguration configuration, string ecosystem, string source)
    {
        var setting = ecosystem switch
        {
            "nuget" => "SupplyChain:NuGetSources",
            "npm" => "SupplyChain:NpmSources",
            _ => null
        };
        if (setting == null) return false;
        var normalized = TrustPattern.NormalizeSource(source);
        var configured = configuration.GetSection(setting).Get<string[]>() ?? [];
        return configured.Any(value => TrustPattern.NormalizeSource(value) == normalized);
    }
}
