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
    public DbSet<Supplier> Suppliers => Set<Supplier>();
    public DbSet<TrustRule> TrustRules => Set<TrustRule>();
    public DbSet<TrustRuleReview> TrustRuleReviews => Set<TrustRuleReview>();
    public DbSet<BlockRule> BlockRules => Set<BlockRule>();
    public DbSet<BlockRuleChange> BlockRuleChanges => Set<BlockRuleChange>();
    public DbSet<PackageArtifact> PackageArtifacts => Set<PackageArtifact>();
    public DbSet<DependencyApplication> DependencyApplications => Set<DependencyApplication>();
    public DbSet<ApplicationPackage> ApplicationPackages => Set<ApplicationPackage>();
    public DbSet<ApplicationEdge> ApplicationEdges => Set<ApplicationEdge>();
    public DbSet<BuildCheck> BuildChecks => Set<BuildCheck>();
    public DbSet<BuildCheckDependency> BuildCheckDependencies => Set<BuildCheckDependency>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityRevision> VulnerabilityRevisions => Set<VulnerabilityRevision>();
    public DbSet<VulnerabilityMatch> VulnerabilityMatches => Set<VulnerabilityMatch>();
    public DbSet<VulnerabilitySyncState> VulnerabilitySyncStates => Set<VulnerabilitySyncState>();
    public DbSet<TrustRuleVulnerabilityExclusion> TrustRuleVulnerabilityExclusions => Set<TrustRuleVulnerabilityExclusion>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApiKey>().HasIndex(k => k.SecretHash).IsUnique();
        builder.Entity<ApiKey>().HasIndex(k => k.UserId);
        builder.Entity<ApiKey>().HasOne(k => k.User).WithMany().HasForeignKey(k => k.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        builder.Entity<Supplier>().HasIndex(s => s.Name).IsUnique();
        builder.Entity<TrustRule>().HasIndex(r => new { r.Ecosystem, r.Status });
        builder.Entity<TrustRule>().HasIndex(r => r.ExpiresAtUtc);
        builder.Entity<TrustRuleReview>().HasIndex(r => new { r.TrustRuleId, r.ReviewedAtUtc });
        builder.Entity<PackageArtifact>().HasIndex(a => a.IdentityKey).IsUnique();
        builder.Entity<PackageArtifact>().HasIndex(a => new { a.Ecosystem, a.Name, a.Version });
        builder.Entity<DependencyApplication>().HasIndex(a => new { a.RequestedByUserId, a.CreatedAtUtc });
        builder.Entity<ApplicationPackage>().HasIndex(p => new { p.ApplicationId, p.PackageArtifactId }).IsUnique();
        builder.Entity<ApplicationEdge>().HasIndex(e => new { e.ApplicationId, e.ParentPackageId, e.ChildPackageId }).IsUnique();
        builder.Entity<BuildCheck>().HasIndex(c => new { c.Project, c.CreatedAtUtc });
        builder.Entity<BuildCheck>().HasIndex(c => new { c.RunId, c.BatchIndex }).IsUnique();
        builder.Entity<BuildCheckDependency>().HasIndex(c => c.BuildCheckId);
        builder.Entity<BlockRule>().HasIndex(r => new { r.Ecosystem, r.Active });
        builder.Entity<Vulnerability>().HasIndex(v => new { v.Ecosystem, v.PackageName });
        builder.Entity<Vulnerability>().HasIndex(v => new { v.Ecosystem, v.PackageName, v.SourceId }).IsUnique();
        builder.Entity<VulnerabilityRevision>().HasIndex(r => new { r.VulnerabilityId, r.ObservedAtUtc });
        builder.Entity<VulnerabilityMatch>().HasIndex(m => new { m.PackageArtifactId, m.VulnerabilityId }).IsUnique();
        builder.Entity<TrustRuleVulnerabilityExclusion>()
            .HasIndex(e => new { e.TrustRuleId, e.VulnerabilityId }).IsUnique();
        builder.Entity<ApplicationEdge>().HasOne(e => e.ParentPackage).WithMany().HasForeignKey(e => e.ParentPackageId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<ApplicationEdge>().HasOne(e => e.ChildPackage).WithMany().HasForeignKey(e => e.ChildPackageId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<BuildCheckDependency>().HasOne(e => e.PackageArtifact).WithMany().HasForeignKey(e => e.PackageArtifactId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<ApplicationPackage>().HasOne(e => e.PackageArtifact).WithMany().HasForeignKey(e => e.PackageArtifactId).OnDelete(DeleteBehavior.Restrict);
    }

    public virtual  Task MigrateAsync(CancellationToken cancellationToken) =>
        Database.MigrateAsync(cancellationToken);

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        foreach (var entry in ChangeTracker.Entries<PackageArtifact>()
                     .Where(e => e.State is EntityState.Added or EntityState.Modified))
        {
            var artifact = entry.Entity;
            artifact.IdentityKey = PackageArtifact.CalculateIdentityKey(artifact.Ecosystem,
                artifact.Name, artifact.Version, artifact.Source, artifact.Sha256);
        }
        return base.SaveChangesAsync(cancellationToken);
    }

    public virtual  Task<bool> CanConnectAsync() =>
        Database.CanConnectAsync();
}
