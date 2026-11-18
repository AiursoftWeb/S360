using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services.AlertMonitoring;

public sealed class BaselineReviewControls(TemplateDbContext db, ILogger<BaselineReviewControls> logger) : IScopedDependency
{
    private const string SettingPrefix = "S360.BaselineReview.Stop.";

    public async Task StopAsync(string repository)
    {
        var key = SettingKey(repository);
        var setting = await db.GlobalSettings.FindAsync(key);
        if (setting == null)
        {
            setting = new GlobalSetting { Key = key };
            db.GlobalSettings.Add(setting);
        }
        setting.Value = JsonSerializer.Serialize(new ReviewStop(repository, DateTime.UtcNow));
        await db.SaveChangesAsync();
    }

    public async Task<HashSet<string>> ReadStoppedAsync()
    {
        var settings = await db.GlobalSettings.AsNoTracking().Where(s => s.Key.StartsWith(SettingPrefix))
            .Select(s => s.Value).ToListAsync();
        var stopped = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in settings)
        {
            var stop = ReadStop(value);
            if (!await HasNewBaselineAsync(stop)) stopped.Add(stop.Repository);
        }
        return stopped;
    }

    // The caller has already verified that this upload completes its run.
    internal async Task<ResumeToken?> FindStopToResumeAsync(BuildCheck last, IReadOnlyCollection<BuildCheck> previous)
    {
        if (last.Project == null || !IsProductionBaseline(last)) return null;
        var repository = RepositoryOf(last.Project);
        if (!BaselineMonitoringService.IsCompanyRepository(repository)) return null;
        var key = SettingKey(repository);
        var value = await db.GlobalSettings.AsNoTracking().Where(s => s.Key == key).Select(s => s.Value).SingleOrDefaultAsync();
        if (value == null) return null;
        var stop = ReadStop(value);
        return last.CreatedAtUtc > stop.StoppedAtUtc && previous.All(b => b.CreatedAtUtc > stop.StoppedAtUtc) &&
            stop.Repository == repository ? new ResumeToken(key, value) : null;
    }

    internal async Task ClearResumedStopAsync(ResumeToken token)
    {
        try
        {
            // The complete report already makes the pause ineffective. Compare the saved marker
            // so a new administrative stop made during the upload survives this cleanup.
            var match = db.GlobalSettings.Where(s => s.Key == token.Key && s.Value == token.Value);
            if (db.Database.IsRelational()) await match.ExecuteDeleteAsync();
            else if (await match.SingleOrDefaultAsync() is { } setting)
            {
                db.GlobalSettings.Remove(setting);
                await db.SaveChangesAsync();
            }
        }
        catch (Exception exception)
        {
            logger.LogWarning("The completed baseline resumed review. Paused review marker cleanup failed with {ExceptionType}.",
                exception.GetType().Name);
        }
    }

    public static string RepositoryOf(string project) => project.Split("//", 2)[0];

    private async Task<bool> HasNewBaselineAsync(ReviewStop stop)
    {
        var solutionPrefix = stop.Repository + "//";
        var checks = await db.BuildChecks.AsNoTracking()
            .Where(c => c.CreatedAtUtc > stop.StoppedAtUtc && c.Project != null &&
                (c.Project == stop.Repository || c.Project.StartsWith(solutionPrefix)))
            .Select(c => new BuildCheck
            {
                Project = c.Project, RunId = c.RunId, BatchIndex = c.BatchIndex, BatchCount = c.BatchCount,
                ScannedProjectCount = c.ScannedProjectCount, Commit = c.Commit, Pipeline = c.Pipeline,
                ContextJson = c.ContextJson, GraphJson = c.GraphJson == null ? null : "[]"
            }).ToListAsync();
        return checks.Where(c => RepositoryOf(c.Project!) == stop.Repository && IsProductionBaseline(c))
            .GroupBy(c => c.RunId).Any(group => BuildCheckRun.IsComplete(group.ToList()));
    }

    private static bool IsProductionBaseline(BuildCheck check) => BuildCheckRun.Purpose(check.ContextJson) == "baseline" &&
        BuildCheckRun.Kind(check.ContextJson) == CheckKind.DefaultBranch;

    private static string SettingKey(string repository) => SettingPrefix + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(repository)));

    private static ReviewStop ReadStop(string? value) => JsonSerializer.Deserialize<ReviewStop>(value ?? "null")
        ?? throw new InvalidOperationException("The repository's baseline review stop is missing.");

    private sealed record ReviewStop(string Repository, DateTime StoppedAtUtc);
    internal sealed record ResumeToken(string Key, string Value);
}
