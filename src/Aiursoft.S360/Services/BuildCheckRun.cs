using Aiursoft.S360.Entities;

namespace Aiursoft.S360.Services;

public static class BuildCheckRun
{
    public static bool IsComplete(IReadOnlyCollection<BuildCheck> batches)
    {
        if (batches.Count == 0) return false;
        var first = batches.First();
        var expected = first.BatchCount;
        if (string.IsNullOrEmpty(first.RunId) || expected < 1 || first.ScannedProjectCount < 1 ||
            batches.Count != expected) return false;
        if (batches.Any(batch => batch.RunId != first.RunId || batch.BatchCount != expected ||
                batch.Project != first.Project || batch.Commit != first.Commit || batch.Pipeline != first.Pipeline ||
                batch.ScannedProjectCount != first.ScannedProjectCount))
            return false;
        return batches.Select(batch => batch.BatchIndex).Order()
            .SequenceEqual(Enumerable.Range(0, expected));
    }
}
