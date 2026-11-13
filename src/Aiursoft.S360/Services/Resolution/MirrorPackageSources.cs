using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services.Resolution;

public class MirrorPackageSource
{
    public string Ecosystem { get; set; } = "";
    public string Source { get; set; } = "";
    public string Upstream { get; set; } = "";
}

public static class MirrorPackageSources
{
    public static string? Upstream(IConfiguration configuration, string ecosystem, string source)
    {
        if (!AllowedPackageSources.Contains(configuration, ecosystem, source)) return null;
        var matches = (configuration.GetSection("SupplyChain:Mirrors").Get<MirrorPackageSource[]>() ?? [])
            .Where(m => m.Ecosystem == ecosystem && TrustPattern.NormalizeSource(m.Source) == TrustPattern.NormalizeSource(source)).ToList();
        if (matches.Count != 1 || !Uri.TryCreate(matches[0].Upstream, UriKind.Absolute, out var upstream) ||
            upstream.Scheme != "https" || !string.IsNullOrEmpty(upstream.UserInfo) ||
            !string.IsNullOrEmpty(upstream.Query) || !string.IsNullOrEmpty(upstream.Fragment)) return null;
        var normalized = TrustPattern.NormalizeSource(upstream.AbsoluteUri);
        return normalized == TrustPattern.NormalizeSource(source) ? null : normalized;
    }
}
