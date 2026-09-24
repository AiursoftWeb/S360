using Aiursoft.S360.Entities;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Tests;

[TestClass]
public class AdvisoryCorrelationTests
{
    [TestMethod]
    public void SharedAndTransitiveAliasesCorrelateWithinOnePackage()
    {
        var advisories = new[]
        {
            Advisory("npm", "sample", "GHSA-first", "[\"CVE-2026-0001\"]"),
            Advisory("npm", "sample", "OSV-second", "[\"CVE-2026-0001\",\"GHSA-third\"]"),
            Advisory("npm", "sample", "GHSA-third", "[]"),
            Advisory("npm", "sample", "GHSA-unrelated", "[]")
        };

        var groups = AdvisoryCorrelation.Group(advisories);

        Assert.HasCount(2, groups);
        Assert.HasCount(3, groups[0]);
        Assert.AreEqual("GHSA-unrelated", groups[1][0].SourceId);
    }

    [TestMethod]
    public void SameIdentifierInOtherPackageOrEcosystemDoesNotCorrelate()
    {
        var advisories = new[]
        {
            Advisory("npm", "sample", "GHSA-first", "[\"CVE-2026-0001\"]"),
            Advisory("npm", "different", "GHSA-second", "[\"CVE-2026-0001\"]"),
            Advisory("nuget", "sample", "GHSA-third", "[\"CVE-2026-0001\"]")
        };

        Assert.HasCount(3, AdvisoryCorrelation.Group(advisories));
    }

    [TestMethod]
    public void MalformedAliasListDoesNotMergeUnrelatedAdvisories()
    {
        var advisories = new[]
        {
            Advisory("npm", "sample", "GHSA-first", "not-json"),
            Advisory("npm", "sample", "GHSA-second", "not-json")
        };

        Assert.HasCount(2, AdvisoryCorrelation.Group(advisories));
    }

    private static Vulnerability Advisory(string ecosystem, string package, string id, string aliases) => new()
    {
        Ecosystem = ecosystem, PackageName = package, SourceId = id, Aliases = aliases
    };
}
