using Aiursoft.S360.Services.Resolution;

namespace Aiursoft.S360.Tests;

[TestClass]
public class AllowedPackageSourcesTests
{
    [TestMethod]
    public void OnlyConfiguredEcosystemSourcesAreAllowed()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SupplyChain:NuGetSources:0"] = "https://nuget.aiursoft.com/v3/index.json",
            ["SupplyChain:NpmSources:0"] = "https://npm.aiursoft.com"
        }).Build();

        Assert.IsTrue(AllowedPackageSources.Contains(configuration, "nuget",
            "https://nuget.aiursoft.com/v3/index.json"));
        Assert.IsTrue(AllowedPackageSources.Contains(configuration, "npm", "https://npm.aiursoft.com/"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "nuget", "https://npm.aiursoft.com"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "npm", "https://127.0.0.1"));
        Assert.IsFalse(AllowedPackageSources.Contains(configuration, "other", "https://nuget.aiursoft.com/v3/index.json"));
    }
}
