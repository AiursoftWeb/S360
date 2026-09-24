using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddSupplyChainCore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BlockRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    PackagePattern = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Active = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlockRules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BuildChecks",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Project = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Commit = table.Column<string>(type: "TEXT", maxLength: 80, nullable: true),
                    Pipeline = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Trusted = table.Column<bool>(type: "INTEGER", nullable: false),
                    VulnerabilityDataCheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BuildChecks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DependencyApplications",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    RequestedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Justification = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Project = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    DirectPackages = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ResolutionContext = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Failure = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DecidedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DecidedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: true),
                    DecisionReason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DependencyApplications", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PackageArtifacts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    IdentityKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastCheckedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PackageArtifacts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Suppliers",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Suppliers", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SourceId = table.Column<string>(type: "TEXT", maxLength: 80, nullable: false),
                    Aliases = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    PackageName = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Severity = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Url = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Withdrawn = table.Column<bool>(type: "INTEGER", nullable: false),
                    ModifiedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FetchedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RawAffectedJson = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VulnerabilitySyncStates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    LastSuccessAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastAttemptAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilitySyncStates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "BlockRuleChanges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    BlockRuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    ChangedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ChangedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlockRuleChanges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BlockRuleChanges_BlockRules_BlockRuleId",
                        column: x => x.BlockRuleId,
                        principalTable: "BlockRules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ApplicationEdges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ApplicationId = table.Column<int>(type: "INTEGER", nullable: false),
                    ParentPackageId = table.Column<int>(type: "INTEGER", nullable: true),
                    ChildPackageId = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApplicationEdges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApplicationEdges_DependencyApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "DependencyApplications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ApplicationEdges_PackageArtifacts_ChildPackageId",
                        column: x => x.ChildPackageId,
                        principalTable: "PackageArtifacts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_ApplicationEdges_PackageArtifacts_ParentPackageId",
                        column: x => x.ParentPackageId,
                        principalTable: "PackageArtifacts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "ApplicationPackages",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ApplicationId = table.Column<int>(type: "INTEGER", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "INTEGER", nullable: false),
                    IsDirect = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApplicationPackages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ApplicationPackages_DependencyApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "DependencyApplications",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ApplicationPackages_PackageArtifacts_PackageArtifactId",
                        column: x => x.PackageArtifactId,
                        principalTable: "PackageArtifacts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "BuildCheckDependencies",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    BuildCheckId = table.Column<int>(type: "INTEGER", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "INTEGER", nullable: false),
                    Trusted = table.Column<bool>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BuildCheckDependencies", x => x.Id);
                    table.ForeignKey(
                        name: "FK_BuildCheckDependencies_BuildChecks_BuildCheckId",
                        column: x => x.BuildCheckId,
                        principalTable: "BuildChecks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_BuildCheckDependencies_PackageArtifacts_PackageArtifactId",
                        column: x => x.PackageArtifactId,
                        principalTable: "PackageArtifacts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "TrustRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SupplierId = table.Column<int>(type: "INTEGER", nullable: false),
                    ApplicationId = table.Column<int>(type: "INTEGER", nullable: true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    PackagePattern = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Version = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    IncludePrerelease = table.Column<bool>(type: "INTEGER", nullable: false),
                    Justification = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    RequestedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrustRules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrustRules_DependencyApplications_ApplicationId",
                        column: x => x.ApplicationId,
                        principalTable: "DependencyApplications",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_TrustRules_Suppliers_SupplierId",
                        column: x => x.SupplierId,
                        principalTable: "Suppliers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VulnerabilityMatches",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilityMatches", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VulnerabilityMatches_PackageArtifacts_PackageArtifactId",
                        column: x => x.PackageArtifactId,
                        principalTable: "PackageArtifacts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_VulnerabilityMatches_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TrustRuleReviews",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TrustRuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    Decision = table.Column<int>(type: "INTEGER", nullable: false),
                    ReviewerId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ReviewedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrustRuleReviews", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrustRuleReviews_TrustRules_TrustRuleId",
                        column: x => x.TrustRuleId,
                        principalTable: "TrustRules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationEdges_ApplicationId_ParentPackageId_ChildPackageId",
                table: "ApplicationEdges",
                columns: new[] { "ApplicationId", "ParentPackageId", "ChildPackageId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationEdges_ChildPackageId",
                table: "ApplicationEdges",
                column: "ChildPackageId");

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationEdges_ParentPackageId",
                table: "ApplicationEdges",
                column: "ParentPackageId");

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationPackages_ApplicationId_PackageArtifactId",
                table: "ApplicationPackages",
                columns: new[] { "ApplicationId", "PackageArtifactId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationPackages_PackageArtifactId",
                table: "ApplicationPackages",
                column: "PackageArtifactId");

            migrationBuilder.CreateIndex(
                name: "IX_BlockRuleChanges_BlockRuleId",
                table: "BlockRuleChanges",
                column: "BlockRuleId");

            migrationBuilder.CreateIndex(
                name: "IX_BlockRules_Ecosystem_Active",
                table: "BlockRules",
                columns: new[] { "Ecosystem", "Active" });

            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId",
                table: "BuildCheckDependencies",
                columns: new[] { "BuildCheckId", "PackageArtifactId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_PackageArtifactId",
                table: "BuildCheckDependencies",
                column: "PackageArtifactId");

            migrationBuilder.CreateIndex(
                name: "IX_BuildChecks_Project_CreatedAtUtc",
                table: "BuildChecks",
                columns: new[] { "Project", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_DependencyApplications_RequestedByUserId_CreatedAtUtc",
                table: "DependencyApplications",
                columns: new[] { "RequestedByUserId", "CreatedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_PackageArtifacts_Ecosystem_Name_Version",
                table: "PackageArtifacts",
                columns: new[] { "Ecosystem", "Name", "Version" });

            migrationBuilder.CreateIndex(
                name: "IX_PackageArtifacts_IdentityKey",
                table: "PackageArtifacts",
                column: "IdentityKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Suppliers_Name",
                table: "Suppliers",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TrustRuleReviews_TrustRuleId_ReviewedAtUtc",
                table: "TrustRuleReviews",
                columns: new[] { "TrustRuleId", "ReviewedAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_ApplicationId",
                table: "TrustRules",
                column: "ApplicationId");

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_Ecosystem_Status",
                table: "TrustRules",
                columns: new[] { "Ecosystem", "Status" });

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_ExpiresAtUtc",
                table: "TrustRules",
                column: "ExpiresAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_SupplierId",
                table: "TrustRules",
                column: "SupplierId");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_Ecosystem_PackageName",
                table: "Vulnerabilities",
                columns: new[] { "Ecosystem", "PackageName" });

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityMatches_PackageArtifactId_VulnerabilityId",
                table: "VulnerabilityMatches",
                columns: new[] { "PackageArtifactId", "VulnerabilityId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityMatches_VulnerabilityId",
                table: "VulnerabilityMatches",
                column: "VulnerabilityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApplicationEdges");

            migrationBuilder.DropTable(
                name: "ApplicationPackages");

            migrationBuilder.DropTable(
                name: "BlockRuleChanges");

            migrationBuilder.DropTable(
                name: "BuildCheckDependencies");

            migrationBuilder.DropTable(
                name: "TrustRuleReviews");

            migrationBuilder.DropTable(
                name: "VulnerabilityMatches");

            migrationBuilder.DropTable(
                name: "VulnerabilitySyncStates");

            migrationBuilder.DropTable(
                name: "BlockRules");

            migrationBuilder.DropTable(
                name: "BuildChecks");

            migrationBuilder.DropTable(
                name: "TrustRules");

            migrationBuilder.DropTable(
                name: "PackageArtifacts");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropTable(
                name: "DependencyApplications");

            migrationBuilder.DropTable(
                name: "Suppliers");
        }
    }
}
