namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class HomeControllerTests : TestBase
{
    [TestMethod]
    public async Task GetIndex()
    {
        var url = "/";
        var response = await Http.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "Know every dependency.");
        StringAssert.Contains(html, "The entire dependency graph");
        StringAssert.Contains(html, "The words behind the workflow");
        StringAssert.Contains(html, "Supplier and source");
        StringAssert.Contains(html, "S360 Web and review");
        Assert.DoesNotContain("template-docs.aiursoft.com", html);
    }
}
