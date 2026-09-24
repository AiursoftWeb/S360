using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
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
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    Ecosystem = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    PackagePattern = table.Column<string>(type: "varchar(214)", maxLength: 214, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Version = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Reason = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Active = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    CreatedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BlockRules", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "BuildChecks",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    Project = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Commit = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Pipeline = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Trusted = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    VulnerabilityDataCheckedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BuildChecks", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "DependencyApplications",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    RequestedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Justification = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Project = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Ecosystem = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Source = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    DirectPackages = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ResolutionContext = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Failure = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Status = table.Column<int>(type: "int", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ResolvedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    DecidedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    DecidedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    DecisionReason = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DependencyApplications", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "PackageArtifacts",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    Ecosystem = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Name = table.Column<string>(type: "varchar(214)", maxLength: 214, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Version = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Source = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    IdentityKey = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Sha256 = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    FirstSeenAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastCheckedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PackageArtifacts", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Suppliers",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    Name = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Suppliers", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    SourceId = table.Column<string>(type: "varchar(80)", maxLength: 80, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Aliases = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Ecosystem = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    PackageName = table.Column<string>(type: "varchar(214)", maxLength: 214, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Summary = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Severity = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Url = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Withdrawn = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    ModifiedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    FetchedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    RawAffectedJson = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "VulnerabilitySyncStates",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    LastSuccessAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    LastAttemptAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    LastError = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilitySyncStates", x => x.Id);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "BlockRuleChanges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    BlockRuleId = table.Column<int>(type: "int", nullable: false),
                    ChangedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Description = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ChangedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ApplicationEdges",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    ApplicationId = table.Column<int>(type: "int", nullable: false),
                    ParentPackageId = table.Column<int>(type: "int", nullable: true),
                    ChildPackageId = table.Column<int>(type: "int", nullable: false)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ApplicationPackages",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    ApplicationId = table.Column<int>(type: "int", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "int", nullable: false),
                    IsDirect = table.Column<bool>(type: "tinyint(1)", nullable: false)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "BuildCheckDependencies",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    BuildCheckId = table.Column<int>(type: "int", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "int", nullable: false),
                    Trusted = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Reason = table.Column<string>(type: "varchar(1000)", maxLength: 1000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "TrustRules",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    SupplierId = table.Column<int>(type: "int", nullable: false),
                    ApplicationId = table.Column<int>(type: "int", nullable: true),
                    Ecosystem = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    PackagePattern = table.Column<string>(type: "varchar(214)", maxLength: 214, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Version = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Source = table.Column<string>(type: "varchar(500)", maxLength: 500, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Sha256 = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: true)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    IncludePrerelease = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    Justification = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RequestedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    RequestedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    Status = table.Column<int>(type: "int", nullable: false)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "VulnerabilityMatches",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    VulnerabilityId = table.Column<int>(type: "int", nullable: false),
                    PackageArtifactId = table.Column<int>(type: "int", nullable: false)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "TrustRuleReviews",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    TrustRuleId = table.Column<int>(type: "int", nullable: false),
                    Decision = table.Column<int>(type: "int", nullable: false),
                    ReviewerId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Reason = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    ReviewedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
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
                })
                .Annotation("MySql:CharSet", "utf8mb4");

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
