using System.Net;
using System.Security.Claims;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class RiskAcceptanceTests : TestBase
{
    private readonly string Source = "https://registry.example/" + Guid.NewGuid().ToString("N");
    private const string Page = "/RiskAcceptance/Index";

    private async Task<int> SeedFinding()
    {
        GetService<IConfiguration>()["SupplyChain:NpmSources:9"] = Source;
        using var scope = Server!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
        var advisory = RiskAcceptancePolicyTests.Advisory(0);
        db.Vulnerabilities.Add(advisory);
        db.Rules.Add(new PackageRule { Ecosystem = "npm", PackagePattern = "picomatch", Source = Source,
            Version = "*", Status = RuleStatus.Approved, RequestedAtUtc = DateTime.UtcNow.AddDays(-1) });
        var audit = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
        if (audit == null) { audit = new VulnerabilitySyncState(); db.VulnerabilitySyncStates.Add(audit); }
        audit.LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2);
        audit.LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-1);
        audit.LastError = null;
        await db.SaveChangesAsync();
        return advisory.Id;
    }

    private Task<HttpResponseMessage> Request(int advisory, string version = "4.0.7") => PostForm("/RiskAcceptance/Submit",
        new Dictionary<string, string>
        {
            ["vulnerabilityId"] = advisory.ToString(), ["version"] = version, ["source"] = Source,
            ["reason"] = "Only reviewed build patterns are evaluated; no user-supplied patterns.",
            ["expiresAtUtc"] = DateTime.UtcNow.AddDays(7).ToString("O")
        }, Page + "?vulnerabilityId=" + advisory);

    [TestMethod]
    public async Task BrowserReviewControlsRealMachineAdmissionAndPreservesHistory()
    {
        await LoginAsAdmin();
        var advisoryId = await SeedFinding();
        using var form = await Http.GetAsync(Page + "?vulnerabilityId=" + advisoryId);
        form.EnsureSuccessStatusCode();
        StringAssert.Contains(await form.Content.ReadAsStringAsync(), "every current and future project");
        using var requested = await Request(advisoryId);
        AssertRedirect(requested, "/RiskAcceptance?filter=pending");
        int id;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var rule = await db.Rules.SingleAsync(r => r.Kind == RuleKind.RiskAcceptance && r.Source == Source);
            Assert.AreEqual(RuleStatus.Pending, rule.Status);
            id = rule.Id;
        }
        using (var noCsrf = await PostForm("/RiskAcceptance/Approve",
            new() { ["id"] = id.ToString(), ["reason"] = "Reviewed" }, includeToken: false))
            Assert.AreEqual(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        using (var approved = await PostForm("/RiskAcceptance/Approve",
            new() { ["id"] = id.ToString(), ["reason"] = "Applicability reviewed for all projects." }, Page + "?filter=all"))
            Assert.AreEqual(HttpStatusCode.Found, approved.StatusCode);
        string secret = Guid.NewGuid().ToString("N");
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var user = await db.Users.SingleAsync(u => u.Email == "admin@default.com");
            db.ApiKeys.Add(new ApiKey { Name = "Risk acceptance test", UserId = user.Id,
                SecretHash = ApiKeyPermissions.Hash(secret), IsEnabled = true, ExpirationTime = DateTime.UtcNow.AddDays(1) });
            await db.SaveChangesAsync();
        }
        Http.DefaultRequestHeaders.Add("X-S360-Key", secret);
        var dependency = new Dependency { Ecosystem = "npm", Name = "picomatch", Version = "4.0.7", Source = Source };
        using (var response = await Http.PostAsJsonAsync("/api/artifacts/mirror/verify", dependency))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsTrue((await response.Content.ReadFromJsonAsync<DependencyDecision>())!.Trusted);
        }
        using (var response = await Http.PostAsJsonAsync("/api/artifacts/assess",
            new ArtifactAssessmentRequest { Dependencies = [dependency] }))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsTrue((await response.Content.ReadFromJsonAsync<ArtifactAssessmentResponse>())!.Decisions.Single().Trusted);
        }
        using (var response = await Http.PostAsJsonAsync("/api/check", new CheckRequest
            { ScannedProjectCount = 1, Dependencies = [dependency] }))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsTrue((await response.Content.ReadFromJsonAsync<CheckResponse>())!.Trusted);
        }
        using (var revoked = await PostForm("/RiskAcceptance/Revoke",
            new() { ["id"] = id.ToString(), ["reason"] = "Input boundary changed." }, Page))
            Assert.AreEqual(HttpStatusCode.Found, revoked.StatusCode);
        using (var response = await Http.PostAsJsonAsync("/api/artifacts/mirror/verify", dependency))
        {
            response.EnsureSuccessStatusCode();
            Assert.IsFalse((await response.Content.ReadFromJsonAsync<DependencyDecision>())!.Trusted);
        }
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            Assert.AreEqual(2, await db.RuleChanges.CountAsync(c => c.RuleId == id));
            Assert.IsFalse((await db.Vulnerabilities.SingleAsync(v => v.Id == advisoryId)).Withdrawn);
            Assert.AreEqual(RuleStatus.Revoked, (await db.Rules.FindAsync(id))!.Status);
        }
        using var history = await Http.GetAsync(Page + "?filter=all");
        history.EnsureSuccessStatusCode();
        StringAssert.Contains(await history.Content.ReadAsStringAsync(), "Input boundary changed.");
    }

    [TestMethod]
    public async Task OrdinaryPackageApprovalPermissionDoesNotGrantRiskAcceptance()
    {
        var (email, password) = await RegisterAndLoginAsync();
        using (var scope = Server!.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = (await users.FindByEmailAsync(email))!;
            await users.AddClaimsAsync(user, [new Claim(AppPermissions.Type, AppPermissionNames.CanReadSupplyChain),
                new Claim(AppPermissions.Type, AppPermissionNames.CanManageTrustRules)]);
        }
        using var login = await PostForm("/Account/Login", new() { ["EmailOrUserName"] = email, ["Password"] = password });
        Assert.AreEqual(HttpStatusCode.Found, login.StatusCode);
        using var response = await PostForm("/RiskAcceptance/Approve", new() { ["id"] = "1", ["reason"] = "Not authorized" }, "/Account/Login");
        Assert.AreEqual(HttpStatusCode.Found, response.StatusCode);
        StringAssert.Contains(response.Headers.Location!.OriginalString, "/Error/Code403");
    }

    [TestMethod]
    public async Task RequestRejectsUnrelatedVersionScope()
    {
        await LoginAsAdmin();
        var id = await SeedFinding();
        using var response = await Request(id, "5.*");
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        using var scope = Server!.Services.CreateScope();
        Assert.IsFalse(await scope.ServiceProvider.GetRequiredService<TemplateDbContext>().Rules
            .AnyAsync(r => r.Kind == RuleKind.RiskAcceptance && r.Source == Source));
    }
}
