using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class PublishSuccessfulAuditRound : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastSuccessfulAttemptAtUtc",
                table: "VulnerabilitySyncStates",
                type: "TEXT",
                nullable: true);

            migrationBuilder.Sql("""
                UPDATE VulnerabilitySyncStates
                SET LastSuccessfulAttemptAtUtc = LastAttemptAtUtc
                WHERE LastSuccessAtUtc IS NOT NULL AND LastAttemptAtUtc <= LastSuccessAtUtc;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastSuccessfulAttemptAtUtc",
                table: "VulnerabilitySyncStates");
        }
    }
}
