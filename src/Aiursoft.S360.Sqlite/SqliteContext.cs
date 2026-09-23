using System.Diagnostics.CodeAnalysis;
using Aiursoft.S360.Entities;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Sqlite;

[ExcludeFromCodeCoverage]

public class SqliteContext(DbContextOptions<SqliteContext> options) : TemplateDbContext(options)
{
    public override Task<bool> CanConnectAsync()
    {
        return Task.FromResult(true);
    }
}
