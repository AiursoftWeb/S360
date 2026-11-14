using System.Diagnostics.CodeAnalysis;
using Aiursoft.DbTools;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Entities;

[ExcludeFromCodeCoverage]

public abstract class TemplateDbContext(DbContextOptions options) : IdentityDbContext<User>(options), ICanMigrate
{
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<GlobalSetting> GlobalSettings => Set<GlobalSetting>();
    public DbSet<PackageRule> Rules => Set<PackageRule>();
    public DbSet<RuleChange> RuleChanges => Set<RuleChange>();
    public DbSet<PackageVersion> PackageVersions => Set<PackageVersion>();
    public DbSet<DependencyApplication> DependencyApplications => Set<DependencyApplication>();
    public DbSet<ApplicationPackage> ApplicationPackages => Set<ApplicationPackage>();
    public DbSet<BuildCheck> BuildChecks => Set<BuildCheck>();
    public DbSet<BuildCheckDependency> BuildCheckDependencies => Set<BuildCheckDependency>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityRevision> VulnerabilityRevisions => Set<VulnerabilityRevision>();
    public DbSet<VulnerabilityMatch> VulnerabilityMatches => Set<VulnerabilityMatch>();
    public DbSet<VulnerabilitySyncState> VulnerabilitySyncStates => Set<VulnerabilitySyncState>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApiKey>().HasIndex(k => k.SecretHash).IsUnique();
        builder.Entity<ApiKey>().HasIndex(k => k.UserId);
        builder.Entity<ApiKey>().HasOne(k => k.User).WithMany().HasForeignKey(k => k.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        builder.Entity<PackageRule>().HasOne(r => r.LegacySourceRule).WithMany()
            .HasForeignKey(r => r.LegacySourceRuleId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<PackageRule>().HasOne(r => r.ParentRule).WithMany()
            .HasForeignKey(r => r.ParentRuleId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<PackageRule>().HasOne(r => r.Vulnerability).WithMany()
            .HasForeignKey(r => r.VulnerabilityId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<PackageRule>().HasIndex(r => new { r.Kind, r.Ecosystem, r.Status });
        builder.Entity<PackageRule>().HasIndex(r => r.ExpiresAtUtc);
        builder.Entity<PackageRule>().HasIndex(r => new { r.ParentRuleId, r.VulnerabilityId }).IsUnique();
        builder.Entity<RuleChange>().HasIndex(r => new { r.RuleId, r.ReviewedAtUtc });
        builder.Entity<PackageVersion>().HasIndex(a => new { a.Ecosystem, a.Name, a.Version });
        builder.Entity<DependencyApplication>().HasIndex(a => new { a.RequestedByUserId, a.CreatedAtUtc });
        builder.Entity<ApplicationPackage>().HasIndex(p => new { p.ApplicationId, p.PackageVersionId }).IsUnique();
        builder.Entity<BuildCheck>().HasIndex(c => new { c.Project, c.CreatedAtUtc });
        builder.Entity<BuildCheck>().HasIndex(c => new { c.RunId, c.BatchIndex }).IsUnique();
        builder.Entity<BuildCheckDependency>().HasIndex(c => c.BuildCheckId);
        builder.Entity<Vulnerability>().HasIndex(v => new { v.Ecosystem, v.PackageName });
        builder.Entity<Vulnerability>().HasIndex(v => new { v.Ecosystem, v.PackageName, v.SourceId }).IsUnique();
        builder.Entity<VulnerabilityRevision>().HasIndex(r => new { r.VulnerabilityId, r.ObservedAtUtc });
        builder.Entity<VulnerabilityMatch>().HasIndex(m => new { m.PackageVersionId, m.VulnerabilityId }).IsUnique();
        builder.Entity<BuildCheckDependency>().HasOne(e => e.PackageVersion).WithMany().HasForeignKey(e => e.PackageVersionId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<ApplicationPackage>().HasOne(e => e.PackageVersion).WithMany().HasForeignKey(e => e.PackageVersionId).OnDelete(DeleteBehavior.Restrict);
    }

    public virtual Task MigrateAsync(CancellationToken cancellationToken) =>
        Database.MigrateAsync(cancellationToken);

    public virtual Task<bool> CanConnectAsync() =>
        Database.CanConnectAsync();
}
