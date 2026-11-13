using System.Net;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Authentication;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class ArtifactAdmissionTests : TestBase
{
    private readonly string _secret = Guid.NewGuid().ToString("N");
    private readonly string Source = "https://registry.example/" + Guid.NewGuid().ToString("N") + "/index.json";
    private Dependency Package(string name) => new()
    {
        Ecosystem = "nuget", Name = name, Version = "1.0.0", Source = Source, Sha256 = new string('a', 64)
    };

    private async Task AuthorizeAsync()
    {
        GetService<IConfiguration>()["SupplyChain:NuGetSources:1"] = Source;
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var user = await db.Users.SingleAsync(u => u.Email == "admin@default.com");
        db.ApiKeys.Add(new ApiKey
        {
            Name = "Mirror fixture", UserId = user.Id, SecretHash = ApiKeyPermissions.Hash(_secret),
            IsEnabled = true, CanPublishBaselines = false, ExpirationTime = DateTime.UtcNow.AddDays(1)
        });
        await db.SaveChangesAsync();
        Http.DefaultRequestHeaders.Add("X-S360-Key", _secret);
    }

    private async Task SeedAsync()
    {
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var now = DateTime.UtcNow;
        foreach (var name in new[] { "Mirror.Blocked", "Mirror.Approved", "Mirror.Unverified" })
        {
            db.TrustRules.Add(new TrustRule
            {
                ApplicationId = null, SupplierId = null,
                Ecosystem = "nuget", PackagePattern = name, Version = "1.*", Source = Source,
                Status = TrustRuleStatus.Approved, ExpiresAtUtc = now.AddDays(1)
            });
            db.PackageArtifacts.Add(new PackageArtifact
            {
                Ecosystem = "nuget", Name = name, Version = "1.0.0", Source = Source,
                Sha256 = new string('a', 64), SourceVerifiedAtUtc = name == "Mirror.Unverified" ? null : now,
                LastCheckedAtUtc = now
            });
        }
        db.BlockRules.Add(new BlockRule
        {
            Ecosystem = "nuget", PackagePattern = "Mirror.Blocked", Version = "*", Active = true, Reason = "Incident"
        });
        var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
        if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
        audit.LastSuccessfulAttemptAtUtc = now.AddSeconds(-1);
        audit.LastSuccessAtUtc = now.AddSeconds(1);
        await db.SaveChangesAsync();
    }

    [TestMethod]
    public async Task OneInternalRulePermitsColdCandidatesButNeverClaimsTheyAreVerified()
    {
        await AuthorizeAsync(); await SeedAsync();
        GetService<IConfiguration>()["SupplyChain:Mirrors:0:Ecosystem"] = "nuget";
        GetService<IConfiguration>()["SupplyChain:Mirrors:0:Source"] = Source;
        GetService<IConfiguration>()["SupplyChain:Mirrors:0:Upstream"] = "https://api.nuget.org/v3/index.json";
        var request = new MirrorCandidateRequest([
            new("nuget", "Mirror.Approved", "1.9.0", Source),
            new("nuget", "Mirror.Approved", "1.9.0-beta", Source),
            new("nuget", "Mirror.Blocked", "1.0.0", Source),
            new("nuget", "Mirror.Unknown", "1.0.0", Source),
            new("nuget", "Mirror.Approved", "1.9.0", "https://api.nuget.org/v3/index.json")]);
        var response = await Http.PostAsJsonAsync("/api/artifacts/mirror/candidates", request);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<MirrorCandidateResponse>();
        Assert.IsNotNull(result);
        CollectionAssert.AreEqual(new[] { true, false, false, false, false }, result.Decisions.Select(d => d.CanFetch).ToArray());
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        Assert.AreEqual(3, await db.PackageArtifacts.CountAsync(a => a.Source == Source));
        Assert.IsFalse(await db.TrustRules.AnyAsync(r => r.Source == "https://api.nuget.org/v3/index.json"));
        (await db.TrustRules.SingleAsync(r => r.PackagePattern == "Mirror.Approved" && r.Source == Source)).Status = TrustRuleStatus.Revoked;
        await db.SaveChangesAsync();
        var revoked = await (await Http.PostAsJsonAsync("/api/artifacts/mirror/candidates", request)).Content.ReadFromJsonAsync<MirrorCandidateResponse>();
        Assert.IsNotNull(revoked);
        Assert.IsFalse(revoked.Decisions[0].CanFetch);
    }

    [TestMethod]
    public async Task EndpointsRequireMachineAuthenticationEvenWhenAnonymousReviewIsEnabled()
    {
        Assert.AreEqual(HttpStatusCode.Unauthorized,
            (await Http.GetAsync("/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(Source))).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized,
            (await Http.PostAsJsonAsync("/api/artifacts/assess", new ArtifactAssessmentRequest { Dependencies = [Package("Mirror.Approved")] })).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized,
            (await Http.PostAsJsonAsync("/api/artifacts/mirror/candidates", new MirrorCandidateRequest([new("nuget", "Mirror.Approved", "1.0.0", Source)]))).StatusCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized,
            (await Http.PostAsJsonAsync("/api/artifacts/mirror/verify", Package("Mirror.Approved"))).StatusCode);
    }

    [TestMethod]
    public async Task EmptyApprovedPageRetainsCursorAndEnumeratesOnlyVerifiedAllowedArtifacts()
    {
        await AuthorizeAsync(); await SeedAsync();
        var url = "/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(Source) + "&take=1";
        var first = await Http.GetFromJsonAsync<ApprovedArtifactPage>(url);
        Assert.IsNotNull(first);
        Assert.IsEmpty(first.Artifacts);
        Assert.IsNotNull(first.NextAfterId);
        var second = await Http.GetFromJsonAsync<ApprovedArtifactPage>(url + $"&afterId={first.NextAfterId}&upperId={first.UpperId}");
        Assert.IsNotNull(second);
        Assert.AreEqual("Mirror.Approved", second.Artifacts.Single().Name);
        Assert.IsNull(second.NextAfterId);
    }

    [TestMethod]
    public async Task AssessmentIsReadOnlyAndRevocationImmediatelyDeniesAnExistingArtifact()
    {
        await AuthorizeAsync(); await SeedAsync();
        int beforeChecks;
        using (var scope = Server!.Services.CreateScope())
            beforeChecks = await scope.ServiceProvider.GetRequiredService<TemplateDbContext>().BuildChecks.CountAsync();
        var input = new ArtifactAssessmentRequest { Dependencies = [Package("Mirror.Approved"), Package("Mirror.Unverified"), Package("Mirror.New")] };
        var result = await (await Http.PostAsJsonAsync("/api/artifacts/assess", input))
            .Content.ReadFromJsonAsync<ArtifactAssessmentResponse>();
        Assert.IsNotNull(result);
        Assert.IsTrue(result.Decisions[0].Trusted);
        Assert.IsTrue(result.Decisions[1].PendingVerification);
        Assert.IsFalse(result.Decisions[2].Trusted);
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.AreEqual(3, await db.PackageArtifacts.CountAsync(a => a.Source == Source));
            Assert.AreEqual(beforeChecks, await db.BuildChecks.CountAsync());
            Assert.IsTrue(await db.PackageArtifacts.Where(a => a.Source == Source).AllAsync(a => a.FirstTrustedAtUtc == null));
            (await db.TrustRules.SingleAsync(r => r.PackagePattern == "Mirror.Approved" && r.Source == Source)).Status = TrustRuleStatus.Revoked;
            await db.SaveChangesAsync();
        }
        var revoked = await (await Http.PostAsJsonAsync("/api/artifacts/assess", input))
            .Content.ReadFromJsonAsync<ArtifactAssessmentResponse>();
        Assert.IsNotNull(revoked);
        Assert.IsFalse(revoked.Decisions[0].Trusted);
        StringAssert.Contains(revoked.Decisions[0].Reason, "revoked");
        var page = await Http.GetFromJsonAsync<ApprovedArtifactPage>("/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(Source));
        Assert.IsNotNull(page);
        Assert.IsEmpty(page.Artifacts);
    }

    [TestMethod]
    public async Task NameFilterReturnsOnlyTheRequestedConcretePackage()
    {
        await AuthorizeAsync(); await SeedAsync();
        var url = "/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(Source);
        var page = await Http.GetFromJsonAsync<ApprovedArtifactPage>(url + "&name=mirror.approved");
        Assert.IsNotNull(page);
        Assert.AreEqual("Mirror.Approved", page.Artifacts.Single().Name);
        var missing = await Http.GetFromJsonAsync<ApprovedArtifactPage>(url + "&name=Mirror.Missing");
        Assert.IsNotNull(missing);
        Assert.IsEmpty(missing.Artifacts);
        Assert.IsNull(missing.NextAfterId);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.GetAsync(url + "&name=Mirror.*")).StatusCode);
        GetService<IConfiguration>()["SupplyChain:NpmSources:1"] = Source;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            db.TrustRules.Add(new TrustRule
            {
                ApplicationId = null, SupplierId = null, Ecosystem = "npm", PackagePattern = "@fixture/ui",
                Version = "1.0.0", Source = Source, Status = TrustRuleStatus.Approved,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            db.PackageArtifacts.Add(new PackageArtifact
            {
                Ecosystem = "npm", Name = "@fixture/ui", Version = "1.0.0", Source = Source,
                Sha256 = new string('a', 64), SourceVerifiedAtUtc = DateTime.UtcNow,
                LastCheckedAtUtc = (await db.VulnerabilitySyncStates.FirstAsync()).LastSuccessfulAttemptAtUtc
            });
            await db.SaveChangesAsync();
        }
        var npm = "/api/artifacts/approved?ecosystem=npm&source=" + Uri.EscapeDataString(Source);
        var exact = await Http.GetFromJsonAsync<ApprovedArtifactPage>(npm + "&name=%40fixture%2Fui");
        Assert.IsNotNull(exact);
        Assert.AreEqual("@fixture/ui", exact.Artifacts.Single().Name);
        var otherCase = await Http.GetFromJsonAsync<ApprovedArtifactPage>(npm + "&name=%40Fixture%2Fui");
        Assert.IsNotNull(otherCase);
        Assert.IsEmpty(otherCase.Artifacts);
    }

    [TestMethod]
    public async Task AdmissionRejectsUnpermittedSourcesAndUnboundedRequests()
    {
        await AuthorizeAsync();
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.PostAsJsonAsync("/api/artifacts/mirror/candidates", new MirrorCandidateRequest([null!]))).StatusCode);
        var package = Package("Mirror.Approved");
        package.Source = "https://unapproved.example/v3/index.json";
        var response = await Http.PostAsJsonAsync("/api/artifacts/assess", new ArtifactAssessmentRequest { Dependencies = [package] });
        var result = await response.Content.ReadFromJsonAsync<ArtifactAssessmentResponse>();
        Assert.IsNotNull(result);
        Assert.IsFalse(result.Decisions.Single().Trusted);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.GetAsync("/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(package.Source))).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.GetAsync("/api/artifacts/approved?ecosystem=nuget&source=" + Uri.EscapeDataString(Source) + "&take=501")).StatusCode);
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.PostAsJsonAsync("/api/artifacts/assess", new ArtifactAssessmentRequest
        { Dependencies = Enumerable.Repeat(Package("Mirror.Approved"), 501).ToList() })).StatusCode);
    }
}
