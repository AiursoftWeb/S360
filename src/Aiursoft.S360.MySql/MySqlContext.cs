using System.Diagnostics.CodeAnalysis;
using Aiursoft.S360.Entities;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.MySql;

[ExcludeFromCodeCoverage]

public class MySqlContext(DbContextOptions<MySqlContext> options) : TemplateDbContext(options);
