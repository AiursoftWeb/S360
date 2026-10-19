using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

namespace Aiursoft.S360.Entities;

public class PackageArtifact
{
    public static string CalculateIdentityKey(string ecosystem, string name, string version,
        string source, string sha256)
    {
        var canonicalName = ecosystem == "nuget" ? name.ToLowerInvariant() : name;
        var identity = $"{ecosystem}\n{canonicalName}\n{version}\n{source}\n{sha256.ToLowerInvariant()}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
    }

    [Key]
    public int Id { get; init; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string Name { get; set; } = string.Empty;
    [MaxLength(128)] public string Version { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string IdentityKey { get; set; } = string.Empty;
    [MaxLength(64)] public string Sha256 { get; set; } = string.Empty;
    public DateTime FirstSeenAtUtc { get; init; } = DateTime.UtcNow;
    public bool SourceVerificationRejected { get; set; }
    public DateTime? SourceVerifiedAtUtc { get; set; }
    public DateTime? FirstTrustedAtUtc { get; set; }
    public DateTime? LastCheckedAtUtc { get; set; }
}
