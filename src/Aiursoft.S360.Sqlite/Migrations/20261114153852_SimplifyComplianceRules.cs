using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    [ExcludeFromCodeCoverage]
    public partial class SimplifyComplianceRules : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // SQLite defers FK changes until table rebuilds. Disable cascades while
            // replacing the referenced table, then restore enforcement below.
            migrationBuilder.Sql("PRAGMA foreign_keys = OFF;", suppressTransaction: true);
            migrationBuilder.DropForeignKey(
                name: "FK_ApplicationPackages_PackageArtifacts_PackageArtifactId",
                table: "ApplicationPackages");

            migrationBuilder.DropForeignKey(
                name: "FK_BuildCheckDependencies_PackageArtifacts_PackageArtifactId",
                table: "BuildCheckDependencies");

            migrationBuilder.DropForeignKey(
                name: "FK_VulnerabilityMatches_PackageArtifacts_PackageArtifactId",
                table: "VulnerabilityMatches");

            migrationBuilder.CreateTable(
                name: "PackageVersions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastCheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PackageVersions", x => x.Id);
                });
            migrationBuilder.CreateTable(
                name: "Rules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    ApplicationId = table.Column<int>(type: "INTEGER", nullable: true),
                    LegacySourceRuleId = table.Column<int>(type: "INTEGER", nullable: true),
                    ParentRuleId = table.Column<int>(type: "INTEGER", nullable: true),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    PackagePattern = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    IncludePrerelease = table.Column<bool>(type: "INTEGER", nullable: false),
                    Justification = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    RequestedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Rules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Rules_DependencyApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "DependencyApplications",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Rules_Rules_LegacySourceRuleId",
                        column: x => x.LegacySourceRuleId,
                        principalTable: "Rules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Rules_Rules_ParentRuleId",
                        column: x => x.ParentRuleId,
                        principalTable: "Rules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Rules_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });
            migrationBuilder.CreateTable(
                name: "RuleChanges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    RuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    Decision = table.Column<int>(type: "INTEGER", nullable: true),
                    ReviewerId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", nullable: false),
                    ReportHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    DecisionBatchId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    ReviewedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RuleChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RuleChanges_Rules_RuleId",
                        column: x => x.RuleId,
                        principalTable: "Rules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Preserve every decision, denial, exclusion and historical review before retiring old tables.
            migrationBuilder.Sql("""
                INSERT INTO PackageVersions (Id,Ecosystem,Name,Version,Source,FirstSeenAtUtc,LastCheckedAtUtc)
                SELECT Id,Ecosystem,Name,Version,Source,FirstSeenAtUtc,LastCheckedAtUtc FROM PackageArtifacts;
                INSERT INTO Rules (Id,Kind,Status,ApplicationId,LegacySourceRuleId,ParentRuleId,VulnerabilityId,
                 Ecosystem,PackagePattern,Version,Source,IncludePrerelease,Justification,RequestedByUserId,RequestedAtUtc,ExpiresAtUtc)
                SELECT t.Id,0,t.Status,t.ApplicationId,NULL,NULL,NULL,t.Ecosystem,
                 CASE WHEN t.PackagePattern LIKE '%*%' THEN t.PackagePattern ELSE COALESCE(p.Name,t.PackagePattern) END,
                 t.Version,t.Source,t.IncludePrerelease,t.Justification,t.RequestedByUserId,t.RequestedAtUtc,t.ExpiresAtUtc
                FROM TrustRules t LEFT JOIN PackagePolicies p ON p.Id=t.PackagePolicyId ORDER BY t.Id;
                UPDATE Rules SET LegacySourceRuleId=(SELECT t.LegacySourceRuleId FROM TrustRules t WHERE t.Id=Rules.Id) WHERE Kind=0;
                INSERT INTO Rules (Id,Kind,Status,ApplicationId,LegacySourceRuleId,ParentRuleId,VulnerabilityId,
                 Ecosystem,PackagePattern,Version,Source,IncludePrerelease,Justification,RequestedByUserId,RequestedAtUtc,ExpiresAtUtc)
                SELECT b.Id+(SELECT COALESCE(MAX(Id),0) FROM TrustRules),1,CASE WHEN b.Active THEN 1 ELSE 3 END,
                 NULL,NULL,NULL,NULL,b.Ecosystem,b.PackagePattern,b.Version,'',1,b.Reason,b.CreatedByUserId,b.CreatedAtUtc,NULL FROM BlockRules b;
                INSERT INTO Rules (Id,Kind,Status,ApplicationId,LegacySourceRuleId,ParentRuleId,VulnerabilityId,
                 Ecosystem,PackagePattern,Version,Source,IncludePrerelease,Justification,RequestedByUserId,RequestedAtUtc,ExpiresAtUtc)
                SELECT e.Id+(SELECT COALESCE(MAX(Id),0) FROM TrustRules)+(SELECT COALESCE(MAX(Id),0) FROM BlockRules),
                 2,1,NULL,NULL,e.TrustRuleId,e.VulnerabilityId,t.Ecosystem,t.PackagePattern,t.Version,t.Source,t.IncludePrerelease,
                 e.Reason,e.CreatedByUserId,e.CreatedAtUtc,NULL
                FROM TrustRuleVulnerabilityExclusions e JOIN TrustRules t ON t.Id=e.TrustRuleId;
                INSERT INTO RuleChanges (Id,RuleId,Decision,ReviewerId,Reason,ReportHash,DecisionBatchId,ReviewedAtUtc,ExpiresAtUtc)
                SELECT Id,TrustRuleId,Decision,ReviewerId,Reason,ReportHash,DecisionBatchId,ReviewedAtUtc,ExpiresAtUtc FROM TrustRuleReviews;
                INSERT INTO RuleChanges (Id,RuleId,Decision,ReviewerId,Reason,ReportHash,DecisionBatchId,ReviewedAtUtc,ExpiresAtUtc)
                SELECT c.Id+(SELECT COALESCE(MAX(Id),0) FROM TrustRuleReviews),
                 c.BlockRuleId+(SELECT COALESCE(MAX(Id),0) FROM TrustRules),NULL,c.ChangedByUserId,c.Description,NULL,NULL,c.ChangedAtUtc,NULL
                FROM BlockRuleChanges c;
                """);

            migrationBuilder.DropTable(
                name: "ApplicationEdges");
            migrationBuilder.DropTable(
                name: "BlockRuleChanges");
            migrationBuilder.DropTable(
                name: "TrustRuleReviews");
            migrationBuilder.DropTable(
                name: "TrustRuleVulnerabilityExclusions");
            migrationBuilder.DropTable(
                name: "PackageArtifacts");
            migrationBuilder.DropTable(
                name: "BlockRules");
            migrationBuilder.DropTable(
                name: "TrustRules");
            migrationBuilder.DropTable(
                name: "PackagePolicies");
            migrationBuilder.DropTable(
                name: "Suppliers");
            migrationBuilder.DropColumn(
                name: "Sha256",
                table: "BuildCheckDependencies");

            migrationBuilder.RenameColumn(
                name: "PackageArtifactId",
                table: "VulnerabilityMatches",
                newName: "PackageVersionId");

            migrationBuilder.RenameIndex(
                name: "IX_VulnerabilityMatches_PackageArtifactId_VulnerabilityId",
                table: "VulnerabilityMatches",
                newName: "IX_VulnerabilityMatches_PackageVersionId_VulnerabilityId");

            migrationBuilder.RenameColumn(
                name: "PackageArtifactId",
                table: "BuildCheckDependencies",
                newName: "PackageVersionId");

            migrationBuilder.RenameIndex(
                name: "IX_BuildCheckDependencies_PackageArtifactId",
                table: "BuildCheckDependencies",
                newName: "IX_BuildCheckDependencies_PackageVersionId");

            migrationBuilder.RenameColumn(
                name: "PackageArtifactId",
                table: "ApplicationPackages",
                newName: "PackageVersionId");

            migrationBuilder.RenameIndex(
                name: "IX_ApplicationPackages_PackageArtifactId",
                table: "ApplicationPackages",
                newName: "IX_ApplicationPackages_PackageVersionId");

            migrationBuilder.RenameIndex(
                name: "IX_ApplicationPackages_ApplicationId_PackageArtifactId",
                table: "ApplicationPackages",
                newName: "IX_ApplicationPackages_ApplicationId_PackageVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_PackageVersions_Ecosystem_Name_Version",
                table: "PackageVersions",
                columns: new[] { "Ecosystem", "Name", "Version" });

            migrationBuilder.CreateIndex(
                name: "IX_RuleChanges_RuleId_ReviewedAtUtc",
                table: "RuleChanges",
                columns: new[] { "RuleId", "ReviewedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_Rules_ApplicationId",
                table: "Rules",
                column: "ApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_ExpiresAtUtc",
                table: "Rules",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_Kind_Ecosystem_Status",
                table: "Rules",
                columns: new[] { "Kind", "Ecosystem", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_Rules_LegacySourceRuleId",
                table: "Rules",
                column: "LegacySourceRuleId");

            migrationBuilder.CreateIndex(
                name: "IX_Rules_ParentRuleId_VulnerabilityId",
                table: "Rules",
                columns: new[] { "ParentRuleId", "VulnerabilityId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Rules_VulnerabilityId",
                table: "Rules",
                column: "VulnerabilityId");

            migrationBuilder.AddForeignKey(
                name: "FK_ApplicationPackages_PackageVersions_PackageVersionId",
                table: "ApplicationPackages",
                column: "PackageVersionId",
                principalTable: "PackageVersions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_BuildCheckDependencies_PackageVersions_PackageVersionId",
                table: "BuildCheckDependencies",
                column: "PackageVersionId",
                principalTable: "PackageVersions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_VulnerabilityMatches_PackageVersions_PackageVersionId",
                table: "VulnerabilityMatches",
                column: "PackageVersionId",
                principalTable: "PackageVersions",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.Sql("PRAGMA foreign_keys = ON;", suppressTransaction: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            throw new NotSupportedException("This migration removes retired file-proof data. Restore the pre-migration database backup to roll back.");
        }
    }
}
