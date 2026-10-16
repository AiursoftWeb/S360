using System.Net;
using Aiursoft.DbTools;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Authorization;
using Microsoft.AspNetCore.Identity;
using Aiursoft.CSTools.Tools;
using static Aiursoft.WebTools.Extends;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class SpecialAccountTests
{
    private HttpClient _http = null!;
    private IHost _server = null!;
    private int _port;

    [TestInitialize]
    public async Task Setup()
    {
        _port = Network.GetAvailablePort();
        var cookieContainer = new CookieContainer();
        var handler = new HttpClientHandler
        {
            CookieContainer = cookieContainer,
            AllowAutoRedirect = false
        };
        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri($"http://localhost:{_port}")
        };

        // Set environment variable for default role
        Environment.SetEnvironmentVariable("AppSettings__DefaultRole", "Administrators");
        
        _server = await AppAsync<Startup>([], port: _port);
        using (var scope = _server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            await db.Database.EnsureDeletedAsync();
        }
        await _server.UpdateDbAsync<TemplateDbContext>();
        await _server.SeedAsync();
        await _server.StartAsync();
    }

    [TestCleanup]
    public async Task Teardown()
    {
        await _server.StopAsync();
        using (var scope = _server.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            await db.Database.EnsureDeletedAsync();
        }
        _server.Dispose();
        Environment.SetEnvironmentVariable("AppSettings__DefaultRole", null);
    }

    [TestMethod]
    public async Task TestRegisterWithDefaultRole()
    {
        var email = $"test-{Guid.NewGuid()}@aiursoft.com";
        var password = "Test-Password-123";

        // Register
        var registerResponse = await PostForm("/Account/Register", new Dictionary<string, string>
        {
            { "Email", email },
            { "Password", password },
            { "ConfirmPassword", password }
        });
        Assert.AreEqual(HttpStatusCode.Found, registerResponse.StatusCode);

        // Verify role
        using (var scope = _server.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var user = await userManager.FindByEmailAsync(email);
            Assert.IsNotNull(user);
            var roles = await userManager.GetRolesAsync(user);
            Assert.IsTrue(roles.Contains("Administrators"));
        }
    }

    [TestMethod]
    public async Task TestSeedDoesNotRecreateDeletedAdmin()
    {
        using (var scope = _server.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var admin = await userManager.FindByNameAsync("admin");
            Assert.IsNotNull(admin);
            Assert.IsTrue((await userManager.DeleteAsync(admin)).Succeeded);
        }

        await _server.SeedAsync();

        using var verification = _server.Services.CreateScope();
        var users = verification.ServiceProvider.GetRequiredService<UserManager<User>>();
        Assert.IsNull(await users.FindByNameAsync("admin"));
    }

    [TestMethod]
    public async Task TestSeedDoesNotRestoreRevokedAdminPermissions()
    {
        using (var scope = _server.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var admin = await userManager.FindByNameAsync("admin");
            var role = await roleManager.FindByNameAsync("Administrators");
            Assert.IsNotNull(admin);
            Assert.IsNotNull(role);
            Assert.IsTrue((await userManager.RemoveFromRoleAsync(admin, "Administrators")).Succeeded);
            foreach (var claim in await roleManager.GetClaimsAsync(role))
            {
                Assert.IsTrue((await roleManager.RemoveClaimAsync(role, claim)).Succeeded);
            }
        }

        await _server.SeedAsync();

        using var verification = _server.Services.CreateScope();
        var users = verification.ServiceProvider.GetRequiredService<UserManager<User>>();
        var roles = verification.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var existingAdmin = await users.FindByNameAsync("admin");
        var existingRole = await roles.FindByNameAsync("Administrators");
        Assert.IsNotNull(existingAdmin);
        Assert.IsNotNull(existingRole);
        Assert.IsFalse(await users.IsInRoleAsync(existingAdmin, "Administrators"));
        Assert.AreEqual(0, (await roles.GetClaimsAsync(existingRole)).Count);
    }

    [TestMethod]
    public async Task TestSeedDoesNotRecreateDeletedAdministratorRole()
    {
        using (var scope = _server.Services.CreateScope())
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var role = await roleManager.FindByNameAsync("Administrators");
            Assert.IsNotNull(role);
            Assert.IsTrue((await roleManager.DeleteAsync(role)).Succeeded);
        }

        await _server.SeedAsync();

        using var verification = _server.Services.CreateScope();
        var roles = verification.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        Assert.IsNull(await roles.FindByNameAsync("Administrators"));
    }

    [TestMethod]
    public async Task TestSeedDoesNotRecreateDeletedEmployeeRole()
    {
        using (var scope = _server.Services.CreateScope())
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var role = await roleManager.FindByNameAsync("Employees");
            Assert.IsNotNull(role);
            Assert.IsTrue((await roleManager.DeleteAsync(role)).Succeeded);
        }

        await _server.SeedAsync();

        using var verification = _server.Services.CreateScope();
        var roles = verification.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        Assert.IsNull(await roles.FindByNameAsync("Employees"));
    }

    [TestMethod]
    public async Task TestSeedDoesNotRestoreRevokedEmployeePermissions()
    {
        using (var scope = _server.Services.CreateScope())
        {
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var role = await roles.FindByNameAsync("Employees");
            Assert.IsNotNull(role);
            foreach (var claim in await roles.GetClaimsAsync(role))
            {
                Assert.IsTrue((await roles.RemoveClaimAsync(role, claim)).Succeeded);
            }
        }

        await _server.SeedAsync();

        using var verification = _server.Services.CreateScope();
        var roleManager = verification.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var employees = await roleManager.FindByNameAsync("Employees");
        Assert.IsNotNull(employees);
        Assert.AreEqual(0, (await roleManager.GetClaimsAsync(employees)).Count);
    }

    [TestMethod]
    public async Task TestSeedCreatesInitialAdminWithAllPermissions()
    {
        using var scope = _server!.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var admin = await users.FindByNameAsync("admin");
        var role = await roles.FindByNameAsync("Administrators");
        Assert.IsNotNull(admin);
        Assert.IsNotNull(role);
        Assert.IsTrue(await users.IsInRoleAsync(admin, "Administrators"));
        var claims = (await roles.GetClaimsAsync(role))
            .Where(c => c.Type == AppPermissions.Type).Select(c => c.Value).ToHashSet();
        CollectionAssert.AreEquivalent(AppPermissions.GetAllPermissions().Select(p => p.Key).ToArray(), claims.ToArray());
        var employees = await roles.FindByNameAsync("Employees");
        Assert.IsNotNull(employees);
        Assert.IsTrue((await roles.GetClaimsAsync(employees)).Any(c =>
            c.Type == AppPermissions.Type && c.Value == AppPermissionNames.CanSubmitDependencyRequests));
    }

    private async Task<string> GetAntiCsrfToken(string url)
    {
        var response = await _http.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        var match = System.Text.RegularExpressions.Regex.Match(html,
            @"<input name=""__RequestVerificationToken"" type=""hidden"" value=""([^""]+)"" />");
        if (!match.Success) throw new InvalidOperationException("Could not find anti-CSRF token");
        return match.Groups[1].Value;
    }

    private async Task<HttpResponseMessage> PostForm(string url, Dictionary<string, string> data)
    {
        var token = await GetAntiCsrfToken(url);
        data["__RequestVerificationToken"] = token;
        return await _http.PostAsync(url, new FormUrlEncodedContent(data));
    }
}
