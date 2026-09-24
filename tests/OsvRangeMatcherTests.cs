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
}
