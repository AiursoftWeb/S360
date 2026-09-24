using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
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
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    TrustRuleId = table.Column<int>(type: "int", nullable: false),
                    VulnerabilityId = table.Column<int>(type: "int", nullable: false),
                    CreatedByUserId = table.Column<string>(type: "varchar(450)", maxLength: 450, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Reason = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
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
                        name: "FK_TrustRuleVulnerabilityExclusions_Vulnerabilities_Vulnerabili~",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

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
