using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
{
    /// <inheritdoc />
    public partial class PreserveAdvisoryRevisions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "VulnerabilityRevisions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    VulnerabilityId = table.Column<int>(type: "int", nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    SourceModifiedAtUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Aliases = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Summary = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Severity = table.Column<string>(type: "varchar(100)", maxLength: 100, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    Withdrawn = table.Column<bool>(type: "tinyint(1)", nullable: false),
                    RawAffectedJson = table.Column<string>(type: "longtext", nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilityRevisions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VulnerabilityRevisions_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityRevisions_VulnerabilityId_ObservedAtUtc",
                table: "VulnerabilityRevisions",
                columns: new[] { "VulnerabilityId", "ObservedAtUtc" });

            // Preserve the current state of any advisory recorded before this migration.
            migrationBuilder.Sql("""
                INSERT INTO `VulnerabilityRevisions`
                    (`VulnerabilityId`, `ObservedAtUtc`, `SourceModifiedAtUtc`, `Aliases`, `Summary`, `Severity`, `Withdrawn`, `RawAffectedJson`)
                SELECT `Id`, `FetchedAtUtc`, `ModifiedAtUtc`, `Aliases`, `Summary`, `Severity`, `Withdrawn`, `RawAffectedJson`
                FROM `Vulnerabilities`;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "VulnerabilityRevisions");
        }
    }
}
