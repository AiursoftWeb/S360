using System.Text.Json;
using System.Text.RegularExpressions;
using Aiursoft.S360.Entities;
using Microsoft.Playwright;
using static Microsoft.Playwright.Assertions;

namespace Aiursoft.S360.Tests.BrowserTests;

[TestClass]
public class NavigationAndApproverBrowserTests : BrowserTestBase
{
    [TestMethod]
    public async Task SidebarNavigationHelpDisclosureAndCopyNudgeWorkInRealBrowser()
    {
        var pageErrors = new List<string>();
        Page.PageError += (_, message) => pageErrors.Add(message);
        await Page.SetViewportSizeAsync(1440, 900);

        await SignInAsAdminAsync();

        // Seed a ReadyForReview request authored by a non-admin employee so reviewer CTA is visible to admin.
        int requestId;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var requester = new User
            {
                UserName = "browser-emp-" + Guid.NewGuid().ToString("N")[..8],
                DisplayName = "Browser Test Employee",
                Email = $"browser-emp-{Guid.NewGuid():N}@aiursoft.com",
                AvatarRelativePath = "avatar/default-avatar.jpg"
            };
            db.Users.Add(requester);
            await db.SaveChangesAsync();

            var app = new DependencyApplication
            {
                RequestedByUserId = requester.Id,
                Ecosystem = "npm",
                Source = "https://registry.npmjs.org/",
                DirectPackages = JsonSerializer.Serialize(new[] { new { Name = "dompurify", Version = "3.2.8" } }),
                Justification = "Browser E2E check for M1 approver loop",
                Project = "AlertCenter",
                ResolutionContext = "npm",
                Status = ApplicationStatus.ReadyForReview
            };
            db.DependencyApplications.Add(app);
            await db.SaveChangesAsync();
            requestId = app.Id;
        }

        try
        {
            await NavigateAsync("/Dashboard/Index");
            // Verify restructured sidebar groups expand cleanly (regression check for valid CSS selector IDs).
            var packagesToggle = Page.Locator("a[data-bs-target='#packages-and-rules']");
            await Expect(packagesToggle).ToBeVisibleAsync();
            await packagesToggle.ClickAsync();
            await Expect(Page.Locator("#packages-and-rules a[href='/SupplyChain/Rules']")).ToBeVisibleAsync();

            var requestsToggle = Page.Locator("a[data-bs-target='#requests']");
            await Expect(requestsToggle).ToBeVisibleAsync();
            await requestsToggle.ClickAsync();
            await Expect(Page.Locator("#requests a[href='/DependencyReviews/Index']")).ToContainTextAsync("Approvals (");
            await CaptureIfRequestedAsync("01-dashboard-sidebar-light.png");

            // Open Create page with prefill query and verify approvers + collapsed help disclosure.
            await NavigateAsync("/DependencyRequests/Create?ecosystem=npm&package=dompurify@3.2.8&project=AlertCenter");
            await Expect(Page.Locator(".s360-approver-directory")).ToContainTextAsync("admin@default.com");
            await Expect(Page.Locator("input[name='project']")).ToHaveValueAsync("AlertCenter");
            await Expect(Page.Locator("textarea[name='directPackages']")).ToHaveValueAsync("dompurify@3.2.8");

            var helpDisclosure = Page.Locator("details.s360-help-disclosure");
            await Expect(helpDisclosure).ToBeVisibleAsync();
            Assert.IsNull(await helpDisclosure.GetAttributeAsync("open"));
            await CaptureIfRequestedAsync("02-create-request-light.png");
            await helpDisclosure.Locator("summary").ClickAsync();
            await Expect(helpDisclosure).ToHaveAttributeAsync("open", "");

            // Open Details page, verify 4-step stepper, copy nudge button, and direct Review CTA.
            await NavigateAsync($"/DependencyRequests/Details/{requestId}");
            await Expect(Page.Locator(".s360-stepper .s360-step")).ToHaveCountAsync(4);
            await Expect(Page.Locator(".s360-approver-directory")).ToContainTextAsync("admin@default.com");

            await Page.Locator("[data-copy-nudge]").ClickAsync();
            await Expect(Page.Locator("[data-nudge-status]")).Not.ToBeEmptyAsync();
            await CaptureIfRequestedAsync("03-request-details-light.png");

            var reviewCta = Page.Locator("a.btn-primary", new() { HasTextString = "Review this request" });
            await Expect(reviewCta).ToBeVisibleAsync();
            await reviewCta.ClickAsync();
            await Expect(Page).ToHaveURLAsync(new Regex($"/DependencyReviews.*#request-{requestId}$", RegexOptions.IgnoreCase));
            await Expect(Page.Locator($"#request-{requestId}")).ToBeVisibleAsync();
            await CaptureIfRequestedAsync("04-reviews-anchor-light.png");

            // Verify dark theme rendering on Request Details (desktop and narrow viewport).
            await Page.EvaluateAsync("() => fetch('/api/switch-theme', { method: 'POST', credentials: 'same-origin' })");
            await NavigateAsync($"/DependencyRequests/Details/{requestId}");
            await Expect(Page.Locator(".s360-stepper .s360-step")).ToHaveCountAsync(4);
            await CaptureIfRequestedAsync("05-request-details-dark.png");

            await Page.SetViewportSizeAsync(430, 900);
            await CaptureIfRequestedAsync("06-request-details-mobile-dark.png");

            Assert.AreEqual(0, pageErrors.Count, "Unexpected page errors: " + string.Join("; ", pageErrors));
        }
        finally
        {
            using var scope = Server!.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var app = await db.DependencyApplications.FindAsync(requestId);
            if (app != null)
            {
                db.DependencyApplications.Remove(app);
                await db.SaveChangesAsync();
            }
        }
    }

    private async Task CaptureIfRequestedAsync(string fileName)
    {
        var dir = Environment.GetEnvironmentVariable("S360_VISUAL_CAPTURE_DIR");
        if (string.IsNullOrWhiteSpace(dir)) return;
        Directory.CreateDirectory(dir);
        await Page.ScreenshotAsync(new PageScreenshotOptions
        {
            Path = Path.Combine(dir, fileName),
            FullPage = true
        });
    }

    private async Task SignInAsAdminAsync()
    {
        await NavigateAsync("/Account/Login");
        var form = Page.Locator("form").Filter(new() { Has = Page.Locator("#EmailOrUserName") });
        await form.Locator("#EmailOrUserName").FillAsync("admin@default.com");
        await form.Locator("#Password").FillAsync("Admin@123456!");
        await form.Locator("button[type=submit]").ClickAsync();
        await Expect(Page).Not.ToHaveURLAsync(new Regex("/Account/Login", RegexOptions.IgnoreCase));
    }

    private async Task NavigateAsync(string path)
    {
        var response = await Page.GotoAsync(path);
        Assert.IsNotNull(response);
        Assert.IsTrue(response.Ok, $"{path}: HTTP {response.Status}");
    }
}
