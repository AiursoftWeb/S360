using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class RecordCheckContext : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ContextJson",
                table: "BuildChecks",
                type: "TEXT",
                maxLength: 6000,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ContextJson",
                table: "BuildChecks");
        }
    }
}
