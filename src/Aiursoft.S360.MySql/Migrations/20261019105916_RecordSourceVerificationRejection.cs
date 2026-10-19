using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
{
    /// <inheritdoc />
    public partial class RecordSourceVerificationRejection : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "SourceVerificationRejected",
                table: "PackageArtifacts",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "SourceVerificationRejected",
                table: "PackageArtifacts");
        }
    }
}
