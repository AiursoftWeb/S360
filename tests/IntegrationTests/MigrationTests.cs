using Aiursoft.S360.MySql;
using Aiursoft.S360.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Aiursoft.S360.Tests.IntegrationTests;

/// <summary>
/// This test class ensures that the Entity Framework migrations are up-to-date for all supported database providers.
/// If you change the database model (entities), you must create a new migration for both SQLite and MySQL.
/// </summary>
[TestClass]
public class MigrationTests
{
    [TestMethod]
    public void TestSqliteMigrations()
    {
        var options = new DbContextOptionsBuilder<SqliteContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
        using var context = new SqliteContext(options);
        var hasPendingChanges = context.Database.HasPendingModelChanges();
        Assert.IsFalse(hasPendingChanges, "There are pending model changes for Sqlite. Please run 'dotnet ef migrations add' for Sqlite.");
    }

    [TestMethod]
    public void TestMySqlMigrations()
    {
        var options = new DbContextOptionsBuilder<MySqlContext>()
            .UseMySql("Server=localhost;Database=test;Uid=root;Pwd=password;", new MySqlServerVersion(new Version(8, 0, 31)))
            .Options;
        using var context = new MySqlContext(options);
        var hasPendingChanges = context.Database.HasPendingModelChanges();
        Assert.IsFalse(hasPendingChanges, "There are pending model changes for MySql. Please run 'dotnet ef migrations add' for MySql.");
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void BuildCheckReportingSqlKeepsForeignKeyIndexed(bool rollback)
    {
        var options = new DbContextOptionsBuilder<MySqlContext>()
            .UseMySql("Server=localhost;Database=test;Uid=root;Pwd=password;",
                new MySqlServerVersion(new Version(9, 7, 0)))
            .Options;
        using var context = new MySqlContext(options);
        const string previous = "20260923091521_AddVulnerabilityAuditState";
        const string reporting = "20260923091740_AddBuildCheckReporting";
        var sql = context.GetService<IMigrator>().GenerateScript(
            rollback ? reporting : previous, rollback ? previous : reporting);
        var replacement = rollback
            ? "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId"
            : "IX_BuildCheckDependencies_BuildCheckId";
        var removed = rollback
            ? "IX_BuildCheckDependencies_BuildCheckId"
            : "IX_BuildCheckDependencies_BuildCheckId_PackageArtifactId";
        var create = sql.IndexOf($"CREATE {(rollback ? "UNIQUE " : "")}INDEX `{replacement}`", StringComparison.Ordinal);
        var drop = sql.IndexOf($"DROP INDEX `{removed}`", StringComparison.Ordinal);
        Assert.IsTrue(create >= 0 && drop > create,
            "MySQL requires a replacement index before dropping the index used by the BuildCheckId foreign key.");
    }
}
