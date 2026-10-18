using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
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
                type: "varchar(6000)",
                maxLength: 6000,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
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
