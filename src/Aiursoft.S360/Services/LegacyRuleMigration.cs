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
        var rules = await db.TrustRules.AsNoTracking().OrderBy(r => r.Id).ToListAsync();
        var artifacts = await db.PackageArtifacts.AsNoTracking().OrderBy(a => a.Id).ToListAsync();
        var reviews = await db.TrustRuleReviews.AsNoTracking().OrderBy(r => r.Id).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.AsNoTracking().OrderBy(e => e.Id).ToListAsync();
        var rows = rules.Where(r => r.IsLegacyTemplate && r.Status == TrustRuleStatus.Approved)
            .SelectMany(rule => artifacts.Where(a => a.Ecosystem == rule.Ecosystem && a.Source == rule.Source &&
                    a.SourceVerifiedAtUtc != null && !a.SourceVerificationRejected &&
                    TrustPattern.Matches(rule.PackagePattern, a.Name, rule.Ecosystem) &&
                    TrustPattern.VersionMatches(rule.Version, a.Version, rule.Ecosystem, rule.IncludePrerelease))
                .DistinctBy(a => PackagePolicy.NormalizeName(a.Ecosystem, a.Name))
                .Where(a => !rules.Any(r => r.LegacySourceRuleId == rule.Id && r.MatchesPackage(a.Name)))
                .Select(a => new LegacyMigrationRow(rule, a.Name)))
            .OrderBy(row => row.Rule.Id).ThenBy(row => row.Name, StringComparer.Ordinal).ToList();
        // Includes authorization history and observed bytes: a stale preview must never overwrite new decisions.
        var fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new { rules, artifacts, reviews, exclusions }))));
        return new LegacyMigrationPlan(fingerprint, rows,
            rules.Where(r => r.IsLegacyTemplate && r.Status is TrustRuleStatus.Rejected or TrustRuleStatus.Revoked).Select(r => r.Id).ToList());
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
        var originals = await db.TrustRules.Include(r => r.Reviews).OrderBy(r => r.Id).ToListAsync();
        var exclusions = await db.TrustRuleVulnerabilityExclusions.Include(e => e.Vulnerability).ToListAsync();
        var batch = Guid.NewGuid().ToString("N");
        foreach (var row in plan.Rows.Where(row => selected.Contains(row.Key)))
        {
            var original = originals.Single(r => r.Id == row.Rule.Id);
            var grant = new TrustRule
            {
                ApplicationId = original.ApplicationId, SupplierId = original.SupplierId,
                Ecosystem = original.Ecosystem, PackagePattern = row.Name, Version = original.Version,
                Source = original.Source, Sha256 = original.Sha256, IncludePrerelease = original.IncludePrerelease,
                Justification = original.Justification, RequestedByUserId = original.RequestedByUserId,
                RequestedAtUtc = original.RequestedAtUtc, ExpiresAtUtc = original.ExpiresAtUtc,
                Status = original.Status, LegacySourceRuleId = original.Id
            };
            db.TrustRules.Add(grant);
            db.TrustRuleReviews.Add(new TrustRuleReview
            {
                TrustRule = grant, TrustRuleId = grant.Id, Decision = grant.Status, ReviewerId = reviewer,
                Reason = reason, DecisionBatchId = batch, ExpiresAtUtc = grant.ExpiresAtUtc
            });
            foreach (var exclusion in exclusions.Where(e => e.TrustRuleId == original.Id &&
                         e.Vulnerability.PackageName.Equals(row.Name, original.Ecosystem == "nuget"
                             ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)))
                db.TrustRuleVulnerabilityExclusions.Add(new TrustRuleVulnerabilityExclusion
                {
                    TrustRule = grant, TrustRuleId = grant.Id, VulnerabilityId = exclusion.VulnerabilityId,
                    CreatedByUserId = exclusion.CreatedByUserId, CreatedAtUtc = exclusion.CreatedAtUtc, Reason = exclusion.Reason
                });
        }
        // Bind every existing exact rule, including rejected/revoked grants, without changing its decision/history.
        foreach (var rule in originals.Where(r => !r.IsLegacyTemplate && r.PackagePolicyId == null))
            db.Entry(rule).Property(r => r.PackagePattern).IsModified = true;
        await db.SaveChangesAsync();
    }
}

public record LegacyMigrationRow(TrustRule Rule, string Name)
{
    public string Key => $"{Rule.Id}:{Name}";
}
public record LegacyMigrationPlan(string Fingerprint, List<LegacyMigrationRow> Rows, List<int> BlockingRuleIds);
