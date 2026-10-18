using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Aiursoft.S360.Entities;

public class ApiKey
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [Required, MaxLength(100)] public string Name { get; set; } = string.Empty;
    [Required, MaxLength(64), JsonIgnore] public string SecretHash { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public User User { get; set; } = null!;
    public bool IsEnabled { get; set; } = true;
    public bool CanPublishBaselines { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpirationTime { get; set; } = DateTime.UtcNow.AddYears(1);
    public DateTime? LastUsed { get; set; }
}
