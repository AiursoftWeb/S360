using Aiursoft.S360.Entities;

namespace Aiursoft.S360.Services.Resolution;

public static class ApplicationPaths
{
    public static Dictionary<int, string> Build(IEnumerable<ApplicationEdge> edges,
        IReadOnlyDictionary<int, PackageArtifact> artifacts)
    {
        var links = edges.ToList();
        var paths = new Dictionary<int, string>();
        var queue = new Queue<int>();
        foreach (var root in links.Where(e => e.ParentPackageId == null))
        {
            if (!artifacts.TryGetValue(root.ChildPackageId, out var artifact)) continue;
            paths[root.ChildPackageId] = artifact.Name;
            queue.Enqueue(root.ChildPackageId);
        }
        while (queue.TryDequeue(out var parent))
        {
            foreach (var edge in links.Where(e => e.ParentPackageId == parent))
            {
                if (paths.ContainsKey(edge.ChildPackageId) || !artifacts.TryGetValue(edge.ChildPackageId, out var child))
                    continue;
                paths[edge.ChildPackageId] = paths[parent] + " → " + child.Name;
                queue.Enqueue(edge.ChildPackageId);
            }
        }
        return paths;
    }
}
