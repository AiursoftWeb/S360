using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.Scanner.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Services;

/// <summary>Explicit, reviewed conversion of legacy allow-prefixes. Never runs at startup.</summary>
public class LegacyRuleMigration(TemplateDbContext db) : IScopedDependency
{
    public async Task<LegacyMigrationPlan> PreviewAsync()
    {
        var rules = await db.Rules.Where(r => r.Kind == RuleKind.Approval).AsNoTracking().OrderBy(r => r.Id).ToListAsync();
        var artifacts = await db.PackageVersions.AsNoTracking().OrderBy(a => a.Id).ToListAsync();
        var reviews = await db.RuleChanges.AsNoTracking().OrderBy(r => r.Id).ToListAsync();
        var exclusions = await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).AsNoTracking().OrderBy(e => e.Id).ToListAsync();
        var rows = rules.Where(r => r.IsLegacyTemplate && r.Status == RuleStatus.Approved)
            .SelectMany(rule => artifacts.Where(a => a.Ecosystem == rule.Ecosystem && a.Source == rule.Source &&

                    TrustPattern.Matches(rule.PackagePattern, a.Name, rule.Ecosystem) &&
                    TrustPattern.VersionMatches(rule.Version, a.Version, rule.Ecosystem, rule.IncludePrerelease))
                .DistinctBy(a => a.Ecosystem == "nuget" ? a.Name.ToLowerInvariant() : a.Name)
                .Where(a => !rules.Any(r => r.LegacySourceRuleId == rule.Id && r.MatchesPackage(a.Name)))
                .Select(a => new LegacyMigrationRow(rule, a.Name)))
            .OrderBy(row => row.Rule.Id).ThenBy(row => row.Name, StringComparer.Ordinal).ToList();
        // Includes authorization history and observed bytes: a stale preview must never overwrite new decisions.
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { rules, artifacts, reviews, exclusions }))));
        return new LegacyMigrationPlan(fingerprint, rows,
            rules.Where(r => r.IsLegacyTemplate && r.Status is RuleStatus.Rejected or RuleStatus.Revoked).Select(r => r.Id).ToList());
    }

    public Task ApplyAsync(string fingerprint, IReadOnlyCollection<string> selections, string reviewer, string reason) =>
        Vulnerability.VulnerabilityAuditSnapshot.ExecuteAsync(db, async () =>
        {
            await ApplyCoreAsync(fingerprint, selections, reviewer, reason);
            return true;
        });

    private async Task ApplyCoreAsync(string fingerprint, IReadOnlyCollection<string> selections, string reviewer, string reason)
    {
        if (string.IsNullOrWhiteSpace(reviewer) || string.IsNullOrWhiteSpace(reason) || reason.Length > 2000)
            throw new ArgumentException("A reviewer and migration reason are required.");
        var plan = await PreviewAsync();
        if (plan.Fingerprint != fingerprint) throw new InvalidOperationException("The migration preview changed. Review it again.");
        if (plan.BlockingRuleIds.Count > 0)
            throw new InvalidOperationException("Legacy wildcard rejections must be reviewed before migration.");
        var selected = selections.ToHashSet(StringComparer.Ordinal);
        if (selected.Count != selections.Count || selected.Any(key => plan.Rows.All(row => row.Key != key)))
            throw new ArgumentException("Select only concrete packages from the current preview.");
        var originals = await db.Rules.Where(r => r.Kind == RuleKind.Approval).Include(r => r.Reviews).OrderBy(r => r.Id).ToListAsync();
        var exclusions = await db.Rules.Where(r => r.Kind == RuleKind.VulnerabilityExclusion).Include(e => e.Vulnerability).ToListAsync();
        var batch = Guid.NewGuid().ToString("N");
        foreach (var row in plan.Rows.Where(row => selected.Contains(row.Key)))
        {
            var original = originals.Single(r => r.Id == row.Rule.Id);
            var grant = new PackageRule
            {
                ApplicationId = original.ApplicationId,
                Ecosystem = original.Ecosystem,
                PackagePattern = row.Name,
                Version = original.Version,
                Source = original.Source,
                IncludePrerelease = original.IncludePrerelease,
                Justification = original.Justification,
                RequestedByUserId = original.RequestedByUserId,
                RequestedAtUtc = original.RequestedAtUtc,
                ExpiresAtUtc = original.ExpiresAtUtc,
                Status = original.Status,
                LegacySourceRuleId = original.Id
            };
            db.Rules.Add(grant);
            db.RuleChanges.Add(new RuleChange
            {
                Rule = grant,
                RuleId = grant.Id,
                Decision = grant.Status,
                ReviewerId = reviewer,
                Reason = reason,
                DecisionBatchId = batch,
                ExpiresAtUtc = grant.ExpiresAtUtc
            });
            foreach (var exclusion in exclusions.Where(e => e.ParentRuleId == original.Id &&
                         e.Vulnerability!.PackageName.Equals(row.Name, original.Ecosystem == "nuget"
                             ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)))
                db.Rules.Add(new PackageRule
                {
                    Kind = RuleKind.VulnerabilityExclusion,
                    Status = RuleStatus.Approved,
                    ParentRule = grant,
                    ParentRuleId = grant.Id,
                    VulnerabilityId = exclusion.VulnerabilityId,
                    RequestedByUserId = exclusion.RequestedByUserId,
                    RequestedAtUtc = exclusion.RequestedAtUtc,
                    Justification = exclusion.Justification
                });
        }
        await db.SaveChangesAsync();
    }
}

public record LegacyMigrationRow(PackageRule Rule, string Name)
{
    public string Key => $"{Rule.Id}:{Name}";
}
public record LegacyMigrationPlan(string Fingerprint, List<LegacyMigrationRow> Rows, List<int> BlockingRuleIds);
