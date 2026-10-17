using System.Text.Json;
using Aiursoft.S360.Services.Vulnerability;

namespace Aiursoft.S360.Tests;

[TestClass]
public class OsvRangeMatcherTests
{
    private const string Range = """
        [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.0.8"}]}]}]
        """;

    [TestMethod]
    public void WildcardStillAllowsVulnerableOldVersionAfterCurrentVersionIsFixed()
    {
        Assert.AreEqual(RangeRisk.Affected, OsvRangeMatcher.Intersects(Range, "nuget", "Example", "10.0.*"));
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(Range, "nuget", "Example", "10.0.8"));
        Assert.AreEqual(RangeRisk.Affected, OsvRangeMatcher.Intersects(Range, "nuget", "Example", "10.0.2"));
    }

    [TestMethod]
    public void FullyExcludedAffectedMinorVersionHasNoRangeRisk()
    {
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(Range, "nuget", "Example", "10.1.*"));
    }

    [TestMethod]
    public void NarrowExclusionCoversEntireAffectedRangeOnlyWhenProven()
    {
        Assert.IsTrue(OsvRangeMatcher.AllAffectedVersionsMatch(Range, "nuget", "Example", "10.0.*", false, false));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(Range, "nuget", "Example", "10.0.*", true, false));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(Range, "nuget", "Example", "10.0.2", false, false));
        const string extendsPastMinor = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"10.0.2"},{"fixed":"10.1.2"}]}]}]
            """;
        const string unknownStart = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"10.0.8"}]}]}]
            """;
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(extendsPastMinor, "nuget", "Example", "10.0.*", false, false));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(unknownStart, "nuget", "Example", "10.0.*", false, false));
    }

    [TestMethod]
    public void ExplicitAffectedVersionsMustAllMatchExclusion()
    {
        const string listed = """
            [{"package":{"ecosystem":"npm","name":"sample"},"versions":["10.0.2","10.0.3"]}]
            """;
        const string partial = """
            [{"package":{"ecosystem":"npm","name":"sample"},"versions":["10.0.2","10.1.0"]}]
            """;
        Assert.IsTrue(OsvRangeMatcher.AllAffectedVersionsMatch(listed, "npm", "sample", "10.0.*", false, false));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(partial, "npm", "sample", "10.0.*", false, false));
    }

    [TestMethod]
    public void UnknownRangeTypeCannotBeTreatedAsClean()
    {
        const string git = """
            [{"package":{"ecosystem":"npm","name":"sample"},"ranges":[{"type":"GIT","events":[{"introduced":"abc"}]}]}]
            """;
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(git, "npm", "sample", "*"));
    }

    [TestMethod]
    public void LastAffectedBoundaryIsInclusive()
    {
        const string range = """
            [{"package":{"ecosystem":"npm","name":"sample"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"2.1.214"}]}]}]
            """;
        Assert.AreEqual(RangeRisk.Affected, OsvRangeMatcher.Intersects(range, "npm", "sample", "2.1.214"));
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(range, "npm", "sample", "2.1.215"));
    }

    [TestMethod]
    public void MalformedOrBackwardsAffectedDataCannotBeTreatedAsClean()
    {
        const string backwards = """
            [{"package":{"ecosystem":"npm","name":"sample"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"1.0.0"}]}]}]
            """;
        const string empty = """
            [{"package":{"ecosystem":"npm","name":"sample"}}]
            """;
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(backwards, "npm", "sample", "1.5.0"));
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(empty, "npm", "sample", "1.5.0"));
    }

    [TestMethod]
    public void EmptyAffectedListsAndEventsCannotBeTreatedAsClean()
    {
        const string emptyLists = """
            [{"package":{"ecosystem":"npm","name":"sample"},"versions":[],"ranges":[]}]
            """;
        const string emptyEvents = """
            [{"package":{"ecosystem":"npm","name":"sample"},"ranges":[{"type":"SEMVER","events":[]}]}]
            """;
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(emptyLists, "npm", "sample", "1.5.0"));
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(emptyEvents, "npm", "sample", "1.5.0"));
    }
    [DataTestMethod]
    [DataRow("8.1.0-beta", "8.1.722-beta", "9.2.1039", RangeRisk.NotAffected)]
    [DataRow("9.1.878-beta", "9.1.893-beta", "9.2.1039", RangeRisk.NotAffected)]
    [DataRow("8.0.0-preview.1.23110.8", "8.0.1", "10.0.13", RangeRisk.NotAffected)]
    [DataRow("7.0.0-preview", "7.1.2", "7.7.1", RangeRisk.NotAffected)]
    [DataRow("2.0.0-preview.11", "2.7.5", "2.7.5", RangeRisk.NotAffected)]
    [DataRow("2.0.0-preview.11", "2.7.5", "2.7.4", RangeRisk.Affected)]
    [DataRow("7.0.0-preview", "7.1.2", "7.0.0", RangeRisk.Affected)]
    [DataRow("1.0.0-beta.2", "1.0.0-beta.10", "1.0.0-beta.9", RangeRisk.Affected)]
    [DataRow("1.0.0-beta.2", "1.0.0-beta.10", "1.0.0-beta.10", RangeRisk.NotAffected)]
    [DataRow("1.0.0-beta", "1.0.0", "1.0.0", RangeRisk.NotAffected)]
    [DataRow("1.0.0-beta", "1.0.1+fixed", "1.0.1+build.2", RangeRisk.NotAffected)]
    [DataRow("1.0.0-beta", "1.0.1", "1.0.0.1", RangeRisk.Affected)]
    public void PrereleaseBoundariesPreserveVulnerableAndFixedVersions(string introduced, string fixedAt,
        string version, RangeRisk expected)
    {
        var affected = JsonSerializer.Serialize(new[] { new
        {
            package = new { ecosystem = "NuGet", name = "Example" },
            ranges = new[] { new { type = "ECOSYSTEM", events = new object[]
                { new { introduced }, new { @fixed = fixedAt } } } }
        } });
        Assert.AreEqual(expected, OsvRangeMatcher.Intersects(affected, "nuget", "Example", version));
    }

    [DataTestMethod]
    [DataRow("1.*", false, RangeRisk.NotAffected)]
    [DataRow("1.*", true, RangeRisk.Affected)]
    [DataRow("*", false, RangeRisk.NotAffected)]
    [DataRow("*", true, RangeRisk.Affected)]
    [DataRow("1.0.0-beta.9", false, RangeRisk.Affected)]
    [DataRow("2.*", true, RangeRisk.NotAffected)]
    public void PrereleaseOnlyRangeRespectsApprovalPrereleasePolicy(string pattern, bool includePrerelease,
        RangeRisk expected)
    {
        const string affected = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0-beta.2"},{"fixed":"1.0.0-rc.1"}]}]}]
            """;
        Assert.AreEqual(expected, OsvRangeMatcher.Intersects(affected, "nuget", "Example", pattern, includePrerelease));
    }

    [TestMethod]
    public void NextMajorsPrereleasesDoNotIntersectWildcard()
    {
        const string affected = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0-beta"},{"fixed":"2.0.1"}]}]}]
            """;
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(affected, "nuget", "Example", "1.*", true));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(affected, "nuget", "Example", "1.*", true, true));

        const string crossesPrefix = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.2.0"},{"fixed":"2.0.0-beta"}]}]}]
            """;
        Assert.IsTrue(OsvRangeMatcher.AllAffectedVersionsMatch(crossesPrefix, "nuget", "Example", "1.*", false, false));
        Assert.IsFalse(OsvRangeMatcher.AllAffectedVersionsMatch(crossesPrefix, "nuget", "Example", "1.*", true, true));
    }

    [TestMethod]
    public void LastAffectedPrereleaseIsInclusiveAndReleaseIsLater()
    {
        const string affected = """
            [{"package":{"ecosystem":"npm","name":"sample"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0-beta.2"},{"last_affected":"1.0.0-rc.1"}]}]}]
            """;
        Assert.AreEqual(RangeRisk.Affected, OsvRangeMatcher.Intersects(affected, "npm", "sample", "1.0.0-rc.1"));
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(affected, "npm", "sample", "1.0.0"));
    }

    [TestMethod]
    public void NugetPrereleaseLabelsIgnoreCaseButNpmLabelsDoNot()
    {
        const string affected = """
            [{"package":{"ecosystem":"NuGet","name":"Example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0-BETA"},{"fixed":"1.0.0-rc"}]}]}]
            """;
        Assert.AreEqual(RangeRisk.NotAffected, OsvRangeMatcher.Intersects(affected, "nuget", "Example", "1.0.0-RC"));
        Assert.AreEqual(RangeRisk.Affected, OsvRangeMatcher.Intersects(affected.Replace("NuGet", "npm"),
            "npm", "Example", "1.0.0-RC"));
    }

    [DataTestMethod]
    [DataRow("1.0.0-beta..1")]
    [DataRow("1.0.0-beta_1")]
    [DataRow("1.0.0-beta.01")]
    [DataRow("1.0.0+")]
    [DataRow("1.0.0+build+again")]
    [DataRow("1.0.0-rc.1", "1.0.0-beta.1")]
    public void UnsupportedOrBackwardsPrereleaseRangesRemainUnknown(string introduced, string fixedAt = "2.0.0")
    {
        var affected = JsonSerializer.Serialize(new[] { new
        {
            package = new { ecosystem = "NuGet", name = "Example" },
            ranges = new[] { new { type = "ECOSYSTEM", events = new object[]
                { new { introduced }, new { @fixed = fixedAt } } } }
        } });
        Assert.AreEqual(RangeRisk.Unknown, OsvRangeMatcher.Intersects(affected, "nuget", "Example", "1.5.0"));
    }
}
