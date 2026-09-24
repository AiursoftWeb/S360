namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class DashboardControllerTests : TestBase
{
    [TestMethod]
    public async Task DashboardRequiresLoginAndExplainsTheWorkspace()
    {
        using var anonymous = await Http.GetAsync("/Dashboard/Index");
        Assert.AreEqual(System.Net.HttpStatusCode.Redirect, anonymous.StatusCode);

        await LoginAsAdmin();
        using var response = await Http.GetAsync("/Dashboard/Index");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Welcome to S360.");
        StringAssert.Contains(html, "Your latest requests");
        StringAssert.Contains(html, "What S360 checks before a dependency is trusted.");
        StringAssert.Contains(html, "Blocklist comes first");
        StringAssert.Contains(html, "Words you will see");
        StringAssert.Contains(html, "Transitive dependency");
        StringAssert.Contains(html, "Artifact SHA-256");
        StringAssert.Contains(html, "For authorized reviewers");
        Assert.DoesNotContain("Hello World!", html);
    }

    [TestMethod]
    public async Task RegularUserDashboardDoesNotRevealOrganizationIndicators()
    {
        await RegisterAndLoginAsync();
        using var response = await Http.GetAsync("/Dashboard/Index");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Your latest requests");
        StringAssert.Contains(html, "Include the whole graph");
        StringAssert.Contains(html, "Words you will see");
        Assert.DoesNotContain("For authorized reviewers", html);
        Assert.DoesNotContain("Across the organization", html);
    }
}
