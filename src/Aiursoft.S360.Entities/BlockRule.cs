using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

public class BlockRule
{
    [Key]
    public int Id { get; init; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string PackagePattern { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = "*";
    [MaxLength(2000)] public string Reason { get; set; } = string.Empty;
    public bool Active { get; set; } = true;
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    [MaxLength(450)] public string CreatedByUserId { get; set; } = string.Empty;
    [InverseProperty(nameof(BlockRuleChange.BlockRule))]
    public IEnumerable<BlockRuleChange> Changes { get; init; } = new List<BlockRuleChange>();
}

public class BlockRuleChange
{
    [Key]
    public int Id { get; init; }
    public required int BlockRuleId { get; set; }
    [JsonIgnore]
    [ForeignKey(nameof(BlockRuleId))]
    [NotNull]
    public BlockRule? BlockRule { get; set; }
    [MaxLength(450)] public string ChangedByUserId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime ChangedAtUtc { get; init; } = DateTime.UtcNow;
}
