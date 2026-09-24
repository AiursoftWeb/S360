using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class AddBuildCheckReporting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId",
                table: "BuildCheckDependencies");

            migrationBuilder.AddColumn<int>(
                name: "BatchCount",
                table: "BuildChecks",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "BatchIndex",
                table: "BuildChecks",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "RunId",
                table: "BuildChecks",
                type: "TEXT",
                maxLength: 32,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AlterColumn<int>(
                name: "PackageArtifactId",
                table: "BuildCheckDependencies",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "INTEGER");

            migrationBuilder.AddColumn<string>(
                name: "Ecosystem",
                table: "BuildCheckDependencies",
                type: "TEXT",
                maxLength: 10,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Name",
                table: "BuildCheckDependencies",
                type: "TEXT",
                maxLength: 214,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Sha256",
                table: "BuildCheckDependencies",
                type: "TEXT",
                maxLength: 64,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "BuildCheckDependencies",
                type: "TEXT",
                maxLength: 500,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Version",
                table: "BuildCheckDependencies",
                type: "TEXT",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_BuildChecks_RunId_BatchIndex",
                table: "BuildChecks",
                columns: new[] { "RunId", "BatchIndex" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId",
                table: "BuildCheckDependencies",
                column: "BuildCheckId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_BuildChecks_RunId_BatchIndex",
                table: "BuildChecks");

            migrationBuilder.DropIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId",
                table: "BuildCheckDependencies");

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
                type: "INTEGER",
                nullable: false,
                defaultValue: 0,
                oldClrType: typeof(int),
                oldType: "INTEGER",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId",
                table: "BuildCheckDependencies",
                columns: new[] { "BuildCheckId", "PackageArtifactId" },
                unique: true);
        }
    }
}
