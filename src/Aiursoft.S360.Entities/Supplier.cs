using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Aiursoft.S360.Entities;

public class Supplier
{
    [Key]
    public int Id { get; init; }
    [MaxLength(128)] public string Name { get; set; } = string.Empty;
    [InverseProperty(nameof(TrustRule.Supplier))]
    public IEnumerable<TrustRule> Rules { get; init; } = new List<TrustRule>();
}
