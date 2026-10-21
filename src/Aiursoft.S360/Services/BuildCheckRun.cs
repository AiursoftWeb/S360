using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;

namespace Aiursoft.S360.Services;

public enum CheckKind { Unknown, Local, MergeRequest, Branch, DefaultBranch, Tag }

public static class BuildCheckRun
{
    /// <summary>Keep legacy repository reports in check history once explicit solution baselines replace them.</summary>
    public static List<BuildCheck> ForEcosystem(IReadOnlyCollection<BuildCheck> checks, string ecosystem)
    {
        var scoped = checks.Where(c => ReadContext(c.ContextJson)?.Ecosystem is not { Length: > 0 } declared ||
            declared == ecosystem).ToList();
        var solutionRepositories = scoped.GroupBy(c => c.RunId).Where(g => IsComplete(g.ToList()))
            .Select(g => ReadContext(g.First().ContextJson))
            .Where(c => c is { Purpose: "baseline", IsAnonymous: false, SolutionPath: not null, Repository: not null })
            .Select(c => c!.Repository!).ToHashSet(StringComparer.Ordinal);
        return scoped.Where(c => Purpose(c.ContextJson) != "baseline" || ReadContext(c.ContextJson)?.SolutionPath != null ||
            c.Project == null || !solutionRepositories.Contains(c.Project)).ToList();
    }

    public static bool IsComplete(IReadOnlyCollection<BuildCheck> batches)
    {
        if (batches.Count == 0) return false;
        var first = batches.First();
        var expected = first.BatchCount;
        if (string.IsNullOrEmpty(first.RunId) || expected < 1 || first.ScannedProjectCount < 1 ||
            batches.Count != expected) return false;
        if (batches.Any(batch => batch.RunId != first.RunId || batch.BatchCount != expected ||
                batch.Project != first.Project || batch.Commit != first.Commit || batch.Pipeline != first.Pipeline ||
                batch.ScannedProjectCount != first.ScannedProjectCount || batch.ContextJson != first.ContextJson ||
                (batch.GraphJson != null) != (first.GraphJson != null)))
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
        if (string.IsNullOrWhiteSpace(context.Ref) || string.IsNullOrWhiteSpace(context.PipelineSource) ||
            string.IsNullOrWhiteSpace(context.DefaultBranch))
            return CheckKind.Unknown;
        return context.Ref == context.DefaultBranch
            ? CheckKind.DefaultBranch : CheckKind.Branch;
    }

    public static string? Purpose(string? json)
    {
        var context = ReadContext(json);
        if (context?.IsAnonymous == true && context.Purpose != "review") return null;
        return context?.Purpose is "review" or "baseline" ? context.Purpose : null;
    }

    public static (string? Purpose, bool Anonymous, CheckKind Kind, string? Ref) ContextKey(BuildCheck check)
    {
        var kind = Kind(check.ContextJson);
        var context = ReadContext(check.ContextJson);
        var purpose = Purpose(check.ContextJson);
        if (purpose == "baseline") return (purpose, false, CheckKind.Unknown, null);
        return (purpose, context?.IsAnonymous == true, kind, kind switch
        {
            CheckKind.MergeRequest => context?.MergeRequest ?? context?.Ref,
            CheckKind.Branch => context?.Ref,
            CheckKind.Tag => context?.Tag,
            _ => null
        });
    }
}
