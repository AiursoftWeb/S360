using System.Text.RegularExpressions;

namespace Aiursoft.S360.SDK;

public static class TrustPattern
{
    public static bool IsValid(string pattern) =>
        !string.IsNullOrWhiteSpace(pattern) && pattern.Length <= 214 &&
        pattern.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '@' or '/' or '*') &&
        (!pattern.Contains('*') || (pattern.Length > 1 && pattern.EndsWith('*') && pattern.Count(c => c == '*') == 1));

    public static bool IsValidConcretePackage(string ecosystem, string name, string version)
    {
        if (ecosystem is not ("nuget" or "npm") || !IsValid(name) ||
            name.Contains('*') || name is "." or ".." ||
            ecosystem == "nuget" && name.Contains('/')) return false;
        var versionPattern = ecosystem == "npm"
            ? @"^[0-9]+(?:\.[0-9]+){2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
            : @"^[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$";
        return !string.IsNullOrWhiteSpace(version) && version.Length <= 128 &&
            Regex.IsMatch(version, versionPattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }

    public static bool Matches(string pattern, string name, string ecosystem)
    {
        var comparison = ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return pattern.EndsWith('*')
            ? name.StartsWith(pattern[..^1], comparison)
            : name.Equals(pattern, comparison);
    }

    public static bool IsValidVersionPattern(string version) =>
        version == "*" ||
        (!string.IsNullOrWhiteSpace(version) && version.Length <= 128 &&
         (version.EndsWith(".*", StringComparison.Ordinal)
             ? version[..^2].Split('.').All(p => int.TryParse(p, out _))
             : !version.Contains('*') && version.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+')));

    public static bool VersionMatches(string pattern, string version, string ecosystem, bool includePrerelease = false)
    {
        if (!IsValidVersionPattern(pattern)) return false;
        if ((pattern == "*" || pattern.EndsWith(".*", StringComparison.Ordinal)) &&
            !includePrerelease && version.Contains('-', StringComparison.Ordinal)) return false;
        var comparison = ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return pattern == "*" ||
               (pattern.EndsWith(".*", StringComparison.Ordinal)
                   ? version.StartsWith(pattern[..^1], comparison)
                   : version.Equals(pattern, comparison));
    }

    public static bool VersionPatternCovers(string outer, string inner, string ecosystem,
        bool outerIncludesPrerelease = false, bool innerIncludesPrerelease = false)
    {
        if (!IsValidVersionPattern(outer) || !IsValidVersionPattern(inner)) return false;
        if (inner == "*")
            return outer == "*" && (outerIncludesPrerelease || !innerIncludesPrerelease);
        if (!inner.EndsWith(".*", StringComparison.Ordinal))
            return VersionMatches(outer, inner, ecosystem, outerIncludesPrerelease);
        if (innerIncludesPrerelease && !outerIncludesPrerelease) return false;
        if (outer == "*") return true;
        if (!outer.EndsWith(".*", StringComparison.Ordinal)) return false;
        var comparison = ecosystem == "nuget" ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return inner.StartsWith(outer[..^1], comparison);
    }

    public static string NormalizeSource(string source)
    {
        if (!Uri.TryCreate(source, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException("Package source must be an HTTPS URL without credentials, query or fragment.");
        }
        return uri.AbsoluteUri.TrimEnd('/');
    }
}
