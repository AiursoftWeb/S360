using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.Entities;

public class Supplier
{
    public int Id { get; set; }
    [MaxLength(128)] public string Name { get; set; } = string.Empty;
    public List<TrustRule> Rules { get; set; } = [];
}
