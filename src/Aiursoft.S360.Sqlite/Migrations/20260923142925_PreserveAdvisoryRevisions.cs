using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
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
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    VulnerabilityId = table.Column<int>(type: "INTEGER", nullable: false),
                    ObservedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SourceModifiedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Aliases = table.Column<string>(type: "TEXT", nullable: false),
                    Summary = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Severity = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Withdrawn = table.Column<bool>(type: "INTEGER", nullable: false),
                    RawAffectedJson = table.Column<string>(type: "TEXT", nullable: false)
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
                });

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityRevisions_VulnerabilityId_ObservedAtUtc",
                table: "VulnerabilityRevisions",
                columns: new[] { "VulnerabilityId", "ObservedAtUtc" });

            // Existing installations already have a current advisory state. Keep it as the
            // first observed revision so a later correction does not erase that baseline.
            migrationBuilder.Sql("""
                INSERT INTO "VulnerabilityRevisions"
                    ("VulnerabilityId", "ObservedAtUtc", "SourceModifiedAtUtc", "Aliases", "Summary", "Severity", "Withdrawn", "RawAffectedJson")
                SELECT "Id", "FetchedAtUtc", "ModifiedAtUtc", "Aliases", "Summary", "Severity", "Withdrawn", "RawAffectedJson"
                FROM "Vulnerabilities";
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
