using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services;

public enum CheckKind { Unknown, Local, MergeRequest, Branch, DefaultBranch, Tag }

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
                batch.ScannedProjectCount != first.ScannedProjectCount || batch.ContextJson != first.ContextJson))
            return false;
        return batches.Select(batch => batch.BatchIndex).Order()
            .SequenceEqual(Enumerable.Range(0, expected));
    }

    public static CheckContext? ReadContext(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<CheckContext>(json); }
        catch (JsonException) { return null; }
    }

    public static CheckKind Kind(string? json)
    {
        var context = ReadContext(json);
        if (context?.Provider == "local") return CheckKind.Local;
        if (context?.Provider != "gitlab") return CheckKind.Unknown;
        if (!string.IsNullOrWhiteSpace(context.MergeRequest) ||
            context.PipelineSource is "merge_request_event" or "external_pull_request_event")
            return CheckKind.MergeRequest;
        if (!string.IsNullOrWhiteSpace(context.Tag)) return CheckKind.Tag;
        if (string.IsNullOrWhiteSpace(context.Ref) || string.IsNullOrWhiteSpace(context.PipelineSource))
            return CheckKind.Unknown;
        return !string.IsNullOrWhiteSpace(context.DefaultBranch) && context.Ref == context.DefaultBranch
            ? CheckKind.DefaultBranch : CheckKind.Branch;
    }

    public static (CheckKind Kind, string? Ref) ContextKey(BuildCheck check)
    {
        var kind = Kind(check.ContextJson);
        var context = ReadContext(check.ContextJson);
        return (kind, kind switch
        {
            CheckKind.MergeRequest => context?.MergeRequest ?? context?.Ref,
            CheckKind.Branch => context?.Ref,
            CheckKind.Tag => context?.Tag,
            _ => null
        });
    }
}
