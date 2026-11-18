namespace Aiursoft.S360.Services;

internal sealed class PolicyPackageNames
{
    public PolicyPackageNames(IEnumerable<(string Ecosystem, string Name)> packages)
    {
        var names = packages.ToLookup(package => package.Ecosystem);
        NuGet = names["nuget"].Select(package => package.Name.ToLowerInvariant()).Distinct().ToArray();
        Npm = names["npm"].Select(package => package.Name).Distinct().ToArray();
    }

    public string[] NuGet { get; }
    public string[] Npm { get; }

    public bool Contains(string ecosystem, string name) => ecosystem switch
    {
        "nuget" => NuGet.Contains(name.ToLowerInvariant()),
        "npm" => Npm.Contains(name),
        _ => false
    };
}
