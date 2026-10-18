using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
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

    [TestMethod]
    public void ContextMustRemainConsistentAcrossBatches()
    {
        var first = Batch(0, 2);
        var second = Batch(1, 2);
        first.ContextJson = JsonSerializer.Serialize(new CheckContext { Provider = "gitlab", Ref = "master",
            DefaultBranch = "master", PipelineSource = "push" });
        second.ContextJson = JsonSerializer.Serialize(new CheckContext { Provider = "gitlab", Ref = "master",
            DefaultBranch = "master", PipelineSource = "merge_request_event", MergeRequest = "42" });
        Assert.IsFalse(BuildCheckRun.IsComplete([first, second]));
        second.ContextJson = first.ContextJson;
        Assert.IsTrue(BuildCheckRun.IsComplete([first, second]));
    }

    [TestMethod]
    [DataRow("push", "master", "master", null, null, CheckKind.DefaultBranch)]
    [DataRow("schedule", "master", "master", null, null, CheckKind.DefaultBranch)]
    [DataRow("merge_request_event", "master", "master", null, null, CheckKind.MergeRequest)]
    [DataRow("push", "master", "master", "42", null, CheckKind.MergeRequest)]
    [DataRow("external_pull_request_event", "master", "master", null, null, CheckKind.MergeRequest)]
    [DataRow("push", "feature", "master", null, null, CheckKind.Branch)]
    [DataRow("push", "v1", "master", null, "v1", CheckKind.Tag)]
    [DataRow(null, "master", "master", null, null, CheckKind.Unknown)]
    [DataRow("push", null, "master", null, null, CheckKind.Unknown)]
    [DataRow("push", "master", null, null, null, CheckKind.Unknown)]
    public void SourceClassificationDoesNotDeclareAuditPurpose(string? source, string? reference,
        string? defaultBranch, string? mergeRequest, string? tag, CheckKind expected)
    {
        var json = JsonSerializer.Serialize(new CheckContext { Provider = "gitlab", PipelineSource = source,
            Ref = reference, DefaultBranch = defaultBranch, MergeRequest = mergeRequest, Tag = tag });
        Assert.AreEqual(expected, BuildCheckRun.Kind(json));
        Assert.IsNull(BuildCheckRun.Purpose(json));
        Assert.AreEqual(CheckKind.Unknown, BuildCheckRun.Kind(null));
        Assert.AreEqual(CheckKind.Unknown, BuildCheckRun.Kind("{invalid"));
        Assert.AreEqual(CheckKind.Local, BuildCheckRun.Kind(JsonSerializer.Serialize(new CheckContext())));
    }

    [TestMethod]
    public void ExplicitPurposeIsIndependentOfBranchAndProvider()
    {
        var first = Batch(0, 1);
        var second = Batch(0, 1);
        first.ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline" });
        second.ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "baseline", Provider = "gitlab",
            Ref = "release", DefaultBranch = "master", PipelineSource = "push" });
        Assert.AreEqual("baseline", BuildCheckRun.Purpose(first.ContextJson));
        Assert.AreEqual(BuildCheckRun.ContextKey(first), BuildCheckRun.ContextKey(second));
        second.ContextJson = JsonSerializer.Serialize(new CheckContext { Purpose = "review", Provider = "gitlab",
            Ref = "master", DefaultBranch = "master", PipelineSource = "push" });
        Assert.AreEqual("review", BuildCheckRun.Purpose(second.ContextJson));
        Assert.AreNotEqual(BuildCheckRun.ContextKey(first), BuildCheckRun.ContextKey(second));
        Assert.IsNull(BuildCheckRun.Purpose(null));
        Assert.IsNull(BuildCheckRun.Purpose("{invalid"));
        Assert.IsNull(BuildCheckRun.Purpose(JsonSerializer.Serialize(new CheckContext { Provider = "gitlab",
            Ref = "master", DefaultBranch = "master", PipelineSource = "push" })));
    }

    private static BuildCheck Batch(int index, int count, string project = "example") => new()
    {
        RunId = new string('a', 32), BatchIndex = index, BatchCount = count,
        ScannedProjectCount = 1,
        Project = project, Commit = "commit", Pipeline = "pipeline"
    };
}
