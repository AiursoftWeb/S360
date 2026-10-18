namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class DashboardControllerTests : TestBase
{
    [TestMethod]
    public async Task DashboardRequiresLoginAndSeparatesOverviewFromInventory()
    {
        using var anonymous = await Http.GetAsync("/Dashboard/Index");
        Assert.AreEqual(System.Net.HttpStatusCode.Redirect, anonymous.StatusCode);

        await LoginAsAdmin();
        using var response = await Http.GetAsync("/Dashboard/Index");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Company overview");
        StringAssert.Contains(html, "Reported projects");
        StringAssert.Contains(html, "Packages in use");
        StringAssert.Contains(html, "Project compliance");
        StringAssert.Contains(html, "Package compliance");
        StringAssert.Contains(html, "My requests");
        Assert.DoesNotContain("s360-inventory-tabs", html);
        Assert.DoesNotContain("s360-dashboard-hero", html);
        Assert.DoesNotContain("Rollout note:", html);
        Assert.DoesNotContain("Hello World!", html);
    }

    [TestMethod]
    public async Task RegularUserDashboardDoesNotRevealOrganizationIndicators()
    {
        await RegisterAndLoginAsync();
        using var response = await Http.GetAsync("/Dashboard/Index");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "My requests");
        Assert.DoesNotContain("Reported projects", html);
        Assert.DoesNotContain("Priority packages", html);
        Assert.DoesNotContain("s360-compliance-chart", html);
        Assert.DoesNotContain("Across the organization", html);
        Assert.DoesNotContain("s360-inventory-tabs", html);
    }
}
