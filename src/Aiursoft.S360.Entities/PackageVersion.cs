using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public class PackageVersion
{
    [Key]
    public int Id { get; init; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string Name { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    public DateTime FirstSeenAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime? LastCheckedAtUtc { get; set; }
}
