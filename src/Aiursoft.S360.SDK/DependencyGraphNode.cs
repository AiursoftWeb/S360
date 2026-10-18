using System.ComponentModel.DataAnnotations;

namespace Aiursoft.S360.SDK;

/// <summary>A node in one manifest/restore-target graph. Children are IDs in that same graph.</summary>
public class DependencyGraphNode
{
    [Required, StringLength(1024)] public string Project { get; set; } = string.Empty;
    [Required, RegularExpression("^(nuget|npm)$")] public string Ecosystem { get; set; } = string.Empty;
    [Required(AllowEmptyStrings = true), StringLength(200)] public string Target { get; set; } = string.Empty;
    [Required, StringLength(1024)] public string Id { get; set; } = string.Empty;
    [Required, RegularExpression("^(root|project|package)$")] public string Kind { get; set; } = "package";
    public Dependency? Package { get; set; }
    [Required, MaxLength(5000)] public List<string> Children { get; set; } = [];

    [System.Text.Json.Serialization.JsonIgnore, Newtonsoft.Json.JsonIgnore]
    public (string Project, string Ecosystem, string Target) Scope => (Project, Ecosystem, Target);

    public static string? Validate(IReadOnlyCollection<DependencyGraphNode> nodes,
        IReadOnlyCollection<Dependency> dependencies, string? ecosystem, bool complete)
    {
        foreach (var node in nodes.Cast<DependencyGraphNode?>())
        {
            if (node == null || !Validator.TryValidateObject(node, new ValidationContext(node), [], true) ||
                node.Children.Any(c => string.IsNullOrWhiteSpace(c) || c.Length > 1024) ||
                node.Children.Distinct(StringComparer.Ordinal).Count() != node.Children.Count ||
                (ecosystem is { Length: > 0 } && node.Ecosystem != ecosystem) ||
                (node.Kind == "package") != (node.Package != null) ||
                (node.Package != null && (node.Package.Ecosystem != node.Ecosystem ||
                    !Validator.TryValidateObject(node.Package, new ValidationContext(node.Package), [], true) ||
                    !TrustPattern.IsValidConcretePackage(node.Package.Ecosystem, node.Package.Name, node.Package.Version))))
                return "Invalid dependency graph node.";
        }
        if (!complete) return null;
        try
        {
            var artifacts = dependencies.Select(DependencyIntroductionPaths.Identity).ToHashSet(StringComparer.Ordinal);
            var graphed = nodes.Where(n => n.Package != null).Select(n => DependencyIntroductionPaths.Identity(n.Package!))
                .ToHashSet(StringComparer.Ordinal);
            if (!artifacts.SetEquals(graphed)) return "Graph packages must exactly match the checked artifacts.";
        }
        catch (ArgumentException) { return "Invalid graph package source."; }
        foreach (var graph in nodes.GroupBy(n => n.Scope))
        {
            var ids = graph.Select(n => n.Id).ToHashSet(StringComparer.Ordinal);
            if (ids.Count != graph.Count() || graph.Count(n => n.Kind == "root") != 1 ||
                graph.SelectMany(n => n.Children).Any(child => !ids.Contains(child)))
                return "A graph must have one root, unique node IDs and no missing edge endpoints.";
        }
        return null;
    }
}
