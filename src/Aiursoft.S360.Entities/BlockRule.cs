using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public class BlockRule
{
    public int Id { get; set; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string PackagePattern { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = "*";
    [MaxLength(2000)] public string Reason { get; set; } = string.Empty;
    public bool Active { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    [MaxLength(450)] public string CreatedByUserId { get; set; } = string.Empty;
    public List<BlockRuleChange> Changes { get; set; } = [];
}

public class BlockRuleChange
{
    public int Id { get; set; }
    public int BlockRuleId { get; set; }
    public BlockRule? BlockRule { get; set; }
    [MaxLength(450)] public string ChangedByUserId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime ChangedAtUtc { get; set; } = DateTime.UtcNow;
}
