using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Resolution;

namespace Aiursoft.S360.Tests;

[TestClass]
public class RequestResolutionPolicyTests
{
    [TestMethod]
    public void QueuedRequestMustRecheckItsSourceAndDirectPackageBeforeDownload()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SupplyChain:NpmSources:0"] = "https://npm.aiursoft.com"
        }).Build();
        var direct = new[] { new DirectPackage("@example/blocked", "1.0.0") };
        RequestResolutionPolicy.ValidateBeforeDownload("npm", "https://npm.aiursoft.com",
            direct, configuration, []);

        var block = new BlockRule
        {
            Ecosystem = "npm", PackagePattern = "@example/*", Version = "*",
            Reason = "Incident response", Active = true
        };
        var blocked = Assert.ThrowsExactly<InvalidOperationException>(() =>
            RequestResolutionPolicy.ValidateBeforeDownload("npm", "https://npm.aiursoft.com",
                direct, configuration, [block]));
        StringAssert.Contains(blocked.Message, "Incident response");
        StringAssert.Contains(blocked.Message, "@example/blocked");

        configuration["SupplyChain:NpmSources:0"] = "https://replacement.example";
        var removedSource = Assert.ThrowsExactly<InvalidOperationException>(() =>
            RequestResolutionPolicy.ValidateBeforeDownload("npm", "https://npm.aiursoft.com",
                direct, configuration, []));
        StringAssert.Contains(removedSource.Message, "no longer permitted");
    }
}
