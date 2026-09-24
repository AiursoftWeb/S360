using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddAdvisoryRangeExclusion : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TrustRuleVulnerabilityExclusions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TrustRuleId = table.Column<int>(type: "INTEGER", nullable: false),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrustRuleVulnerabilityExclusions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrustRuleVulnerabilityExclusions_TrustRules_TrustRuleId",
                        column: x => x.TrustRuleId,
                        principalTable: "TrustRules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_TrustRuleVulnerabilityExclusions_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrustRuleVulnerabilityExclusions_TrustRuleId_VulnerabilityId",
                table: "TrustRuleVulnerabilityExclusions",
                columns: new[] { "TrustRuleId", "VulnerabilityId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_TrustRuleVulnerabilityExclusions_VulnerabilityId",
                table: "TrustRuleVulnerabilityExclusions",
                column: "VulnerabilityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TrustRuleVulnerabilityExclusions");
        }
    }
}
