using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.MySql.Migrations
{
    /// <inheritdoc />
    public partial class AddBuildCheckReporting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Keep the BuildCheckId foreign key indexed while replacing its index.
            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId",
                table: "BuildCheckDependencies",
                column: "BuildCheckId");

            migrationBuilder.DropIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId",
                table: "BuildCheckDependencies");

            migrationBuilder.AddColumn<int>(
                name: "BatchCount",
                table: "BuildChecks",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "BatchIndex",
                table: "BuildChecks",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "RunId",
                table: "BuildChecks",
                type: "varchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AlterColumn<int>(
                name: "PackageArtifactId",
                table: "BuildCheckDependencies",
                type: "int",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "int");

            migrationBuilder.AddColumn<string>(
                name: "Ecosystem",
                table: "BuildCheckDependencies",
                type: "varchar(10)",
                maxLength: 10,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Name",
                table: "BuildCheckDependencies",
                type: "varchar(214)",
                maxLength: 214,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Sha256",
                table: "BuildCheckDependencies",
                type: "varchar(64)",
                maxLength: 64,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "BuildCheckDependencies",
                type: "varchar(500)",
                maxLength: 500,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Version",
                table: "BuildCheckDependencies",
                type: "varchar(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "")
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_BuildChecks_RunId_BatchIndex",
                table: "BuildChecks",
                columns: new[] { "RunId", "BatchIndex" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_BuildChecks_RunId_BatchIndex",
                table: "BuildChecks");

            migrationBuilder.DropColumn(
                name: "BatchCount",
                table: "BuildChecks");

            migrationBuilder.DropColumn(
                name: "BatchIndex",
                table: "BuildChecks");

            migrationBuilder.DropColumn(
                name: "RunId",
                table: "BuildChecks");

            migrationBuilder.DropColumn(
                name: "Ecosystem",
                table: "BuildCheckDependencies");

            migrationBuilder.DropColumn(
                name: "Name",
                table: "BuildCheckDependencies");

            migrationBuilder.DropColumn(
                name: "Sha256",
                table: "BuildCheckDependencies");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "BuildCheckDependencies");

            migrationBuilder.DropColumn(
                name: "Version",
                table: "BuildCheckDependencies");

            migrationBuilder.AlterColumn<int>(
                name: "PackageArtifactId",
                table: "BuildCheckDependencies",
                type: "int",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "int",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId",
                table: "BuildCheckDependencies",
                columns: new[] { "BuildCheckId", "PackageArtifactId" },
                unique: true);

            migrationBuilder.DropIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId",
                table: "BuildCheckDependencies");
        }
    }
}
