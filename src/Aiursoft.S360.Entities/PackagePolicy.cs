using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Aiursoft.S360.Entities;

/// <summary>A concrete package at one registry. Authorization belongs to its version grants.</summary>
public class PackagePolicy
{
    [Key] public int Id { get; init; }
    [MaxLength(10)] public string Ecosystem { get; set; } = string.Empty;
    [MaxLength(214)] public string Name { get; set; } = string.Empty;
    [MaxLength(214)] public string NormalizedName { get; set; } = string.Empty;
    [MaxLength(500)] public string Source { get; set; } = string.Empty;
    [MaxLength(64)] public string IdentityKey { get; set; } = string.Empty;
    [JsonIgnore] public ICollection<TrustRule> Grants { get; init; } = new List<TrustRule>();

    public static string NormalizeName(string ecosystem, string name) =>
        ecosystem == "nuget" ? name.ToLowerInvariant() : name;

    public static string CalculateIdentityKey(string ecosystem, string name, string source) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{ecosystem}\n{NormalizeName(ecosystem, name)}\n{source}")));
}
