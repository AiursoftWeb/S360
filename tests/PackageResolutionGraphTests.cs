using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Resolution;

namespace Aiursoft.S360.Tests;

[TestClass]
public class PackageResolutionGraphTests
{
    [TestMethod]
    [DataRow("nuget", "Example.Library")]
    [DataRow("npm", "@example/library")]
    public async Task RequestRecordsOnlySuppliedIdentitiesWithoutAnAccessibleRegistry(string ecosystem, string name)
    {
        var report = await new PackageResolutionService().ResolveAsync(ecosystem,
            "https://unreachable.invalid/registry", [new DirectPackage(name, "1.2.3")]);
        Assert.HasCount(1, report.Dependencies);
        Assert.AreEqual(name, report.Dependencies[0].Name);
        Assert.AreEqual("1.2.3", report.Dependencies[0].Version);
        StringAssert.Contains(report.Context, "transitive dependencies are reported by CI");
    }

    [TestMethod]
    public void ReviewFingerprintBindsTheRequestedListAndDetectsChanges()
    {
        var root = new Dependency { Ecosystem = "nuget", Name = "A", Version = "1.0.0", Source = "https://registry.example" };
        var child = new Dependency { Ecosystem = root.Ecosystem, Name = "B", Version = "2.0.0", Source = root.Source };
        var report = new ResolutionReport([root, child], [new(null, root), new(root, child)], [], "Historical report");
        var application = new DependencyApplication
        {
            Ecosystem = root.Ecosystem,
            Source = root.Source,
            ResolutionContext = report.Context,
            DirectPackages = """[{"Name":"A","Version":"1.0.0"}]""",
            Packages = [
                new ApplicationPackage { ApplicationId = 0, PackageVersionId = 1, IsDirect = true,
                    PackageVersion = new PackageVersion { Id = 1, Ecosystem = root.Ecosystem, Name = root.Name, Version = root.Version, Source = root.Source } },
                new ApplicationPackage { ApplicationId = 0, PackageVersionId = 2,
                    PackageVersion = new PackageVersion { Id = 2, Ecosystem = child.Ecosystem, Name = child.Name, Version = child.Version, Source = child.Source } }
            ]
        };
        var fingerprint = ReportFingerprint.Compute(application, report);
        Assert.AreEqual(fingerprint, ReportFingerprint.ComputePersisted(application));
        application.Packages.Last().PackageVersion.Version = "2.0.1";
        Assert.AreNotEqual(fingerprint, ReportFingerprint.ComputePersisted(application));
        application.Packages.Last().PackageVersion.Version = child.Version;
        application.Packages.Last().PackageVersion.Source = "https://different.example";
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
        application.Packages.Last().PackageVersion.Source = child.Source;
        application.Packages.Last().IsDirect = true;
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
        application.Packages.Last().IsDirect = false;
        application.DirectPackages = "not JSON";
        Assert.ThrowsExactly<InvalidOperationException>(() => ReportFingerprint.ComputePersisted(application));
    }
}
