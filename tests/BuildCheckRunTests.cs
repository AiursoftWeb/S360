using Aiursoft.S360.Entities;
using Aiursoft.S360.Services;

namespace Aiursoft.S360.Tests;

[TestClass]
public class BuildCheckRunTests
{
    [TestMethod]
    public void CompleteRunRequiresEveryConsistentBatch()
    {
        var first = Batch(0, 2);
        var second = Batch(1, 2);
        Assert.IsFalse(BuildCheckRun.IsComplete([first]));
        Assert.IsTrue(BuildCheckRun.IsComplete([second, first]));
        Assert.IsFalse(BuildCheckRun.IsComplete([first, Batch(1, 3)]));
        Assert.IsFalse(BuildCheckRun.IsComplete([first, Batch(2, 3)]));
        Assert.IsFalse(BuildCheckRun.IsComplete([first, Batch(1, 2, "different")]));
        var differentCount = Batch(1, 2);
        differentCount.ScannedProjectCount = 2;
        Assert.IsFalse(BuildCheckRun.IsComplete([first, differentCount]));
    }

    private static BuildCheck Batch(int index, int count, string project = "example") => new()
    {
        RunId = new string('a', 32), BatchIndex = index, BatchCount = count,
        ScannedProjectCount = 1,
        Project = project, Commit = "commit", Pipeline = "pipeline"
    };
}
