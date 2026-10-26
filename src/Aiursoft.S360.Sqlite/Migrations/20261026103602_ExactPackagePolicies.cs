using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Aiursoft.S360.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class ExactPackagePolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "LegacySourceRuleId",
                table: "TrustRules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "PackagePolicyId",
                table: "TrustRules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "PackagePolicies",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Ecosystem = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    NormalizedName = table.Column<string>(type: "TEXT", maxLength: 214, nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    IdentityKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PackagePolicies", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_LegacySourceRuleId",
                table: "TrustRules",
                column: "LegacySourceRuleId");

            migrationBuilder.CreateIndex(
                name: "IX_TrustRules_PackagePolicyId",
                table: "TrustRules",
                column: "PackagePolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_PackagePolicies_IdentityKey",
                table: "PackagePolicies",
                column: "IdentityKey",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_TrustRules_PackagePolicies_PackagePolicyId",
                table: "TrustRules",
                column: "PackagePolicyId",
                principalTable: "PackagePolicies",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_TrustRules_TrustRules_LegacySourceRuleId",
                table: "TrustRules",
                column: "LegacySourceRuleId",
                principalTable: "TrustRules",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_TrustRules_PackagePolicies_PackagePolicyId",
                table: "TrustRules");

            migrationBuilder.DropForeignKey(
                name: "FK_TrustRules_TrustRules_LegacySourceRuleId",
                table: "TrustRules");

            migrationBuilder.DropTable(
                name: "PackagePolicies");

            migrationBuilder.DropIndex(
                name: "IX_TrustRules_LegacySourceRuleId",
                table: "TrustRules");

            migrationBuilder.DropIndex(
                name: "IX_TrustRules_PackagePolicyId",
                table: "TrustRules");

            migrationBuilder.DropColumn(
                name: "LegacySourceRuleId",
                table: "TrustRules");

            migrationBuilder.DropColumn(
                name: "PackagePolicyId",
                table: "TrustRules");
        }
    }
}
