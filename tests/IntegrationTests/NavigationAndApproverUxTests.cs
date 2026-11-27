using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class NavigationAndApproverUxTests : TestBase
{
    [TestMethod]
    public async Task SidebarShowsRestructuredGroupsPendingCountAndPreciseActiveGroup()
    {
        await LoginAsAdmin();

        int baselinePending;
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            baselinePending = await db.DependencyApplications.CountAsync(a => a.Status == ApplicationStatus.ReadyForReview);
        }

        using (var initial = await Http.GetAsync("/Dashboard/Index"))
        {
            initial.EnsureSuccessStatusCode();
            var html = await initial.Content.ReadAsStringAsync();
            StringAssert.Contains(html, "Overview");
            StringAssert.Contains(html, "Supply chain");
            StringAssert.Contains(html, "Account & Admin");
            StringAssert.Contains(html, "Compliance");
            StringAssert.Contains(html, "Packages and rules");
            StringAssert.Contains(html, "Requests");
            StringAssert.Contains(html, "Projects");
            StringAssert.Contains(html, "Rules & packages");
            StringAssert.Contains(html, "Blocklist");
            StringAssert.Contains(html, "Request a package");
            StringAssert.Contains(html, "My requests");
            StringAssert.Contains(html, "Approvals");
            StringAssert.Contains(html, "AlertCenter");
            if (baselinePending == 0)
            {
                Assert.DoesNotContain("Approvals (", html);
            }
            else
            {
                StringAssert.Contains(html, $"Approvals ({baselinePending})");
            }
        }

        List<int> seededIds = [];
        try
        {
            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var admin = await db.Users.SingleAsync(u => u.Email == "admin@default.com");
                var first = new DependencyApplication
                {
                    RequestedByUserId = admin.Id,
                    Ecosystem = "nuget",
                    Source = "https://api.nuget.org/v3/index.json",
                    DirectPackages = JsonSerializer.Serialize(new[] { new { Name = "Sample.One", Version = "1.0.0" } }),
                    Justification = "Pending request 1",
                    ResolutionContext = "net10.0",
                    Status = ApplicationStatus.ReadyForReview
                };
                var second = new DependencyApplication
                {
                    RequestedByUserId = admin.Id,
                    Ecosystem = "npm",
                    Source = "https://registry.npmjs.org/",
                    DirectPackages = JsonSerializer.Serialize(new[] { new { Name = "sample-two", Version = "2.0.0" } }),
                    Justification = "Pending request 2",
                    ResolutionContext = "npm",
                    Status = ApplicationStatus.ReadyForReview
                };
                db.DependencyApplications.AddRange(first, second);
                await db.SaveChangesAsync();
                seededIds.AddRange([first.Id, second.Id]);
            }

            using (var withPending = await Http.GetAsync("/Dashboard/Index"))
            {
                withPending.EnsureSuccessStatusCode();
                var html = await withPending.Content.ReadAsStringAsync();
                StringAssert.Contains(html, $"Approvals ({baselinePending + 2})");
            }

            // Verify SupplyChain routes activate only their own sidebar group (not both Compliance and Packages and rules).
            using (var projectsPage = await Http.GetAsync("/SupplyChain/Index?tab=projects"))
            {
                projectsPage.EnsureSuccessStatusCode();
                var html = await projectsPage.Content.ReadAsStringAsync();
                AssertSidebarItemActive(html, "Compliance", expectedActive: true);
                AssertSidebarItemActive(html, "Packages and rules", expectedActive: false);
            }

            using (var rulesPage = await Http.GetAsync("/SupplyChain/Index?tab=rules"))
            {
                rulesPage.EnsureSuccessStatusCode();
                var html = await rulesPage.Content.ReadAsStringAsync();
                AssertSidebarItemActive(html, "Compliance", expectedActive: false);
                AssertSidebarItemActive(html, "Packages and rules", expectedActive: true);
            }

            using (var blocklistPage = await Http.GetAsync("/SupplyChain/Blocklist?ecosystem=nuget"))
            {
                blocklistPage.EnsureSuccessStatusCode();
                var html = await blocklistPage.Content.ReadAsStringAsync();
                AssertSidebarItemActive(html, "Compliance", expectedActive: false);
                AssertSidebarItemActive(html, "Packages and rules", expectedActive: true);
            }

            // Legacy redirect /SupplyChain/Rules stays compatible.
            using (var legacyRules = await Http.GetAsync("/SupplyChain/Rules"))
            {
                AssertRedirect(legacyRules, "/SupplyChain?tab=rules");
            }
        }
        finally
        {
            if (seededIds.Count > 0)
            {
                using var scope = Server!.Services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var toRemove = await db.DependencyApplications.Where(a => seededIds.Contains(a.Id)).ToListAsync();
                db.DependencyApplications.RemoveRange(toRemove);
                await db.SaveChangesAsync();
            }
        }
    }

    [TestMethod]
    public async Task SidebarHidesReviewerAndAdminEntriesForRegularEmployee()
    {
        var (email, password) = await RegisterAndLoginAsync();
        await GrantPermissionsAndReloginAsync(email, password, AppPermissionNames.CanSubmitDependencyRequests);

        using var response = await Http.GetAsync("/Dashboard/Index");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();

        StringAssert.Contains(html, "Rules & packages");
        StringAssert.Contains(html, "Request a package");
        StringAssert.Contains(html, "My requests");
        StringAssert.Contains(html, "Profile Settings");

        Assert.DoesNotContain("href=\"/SupplyChain/Index\"", html);
        Assert.DoesNotContain("href=\"/DependencyReviews/Index\"", html);
        Assert.DoesNotContain("href=\"/SupplyChain/Blocklist\"", html);
        Assert.DoesNotContain("href=\"/AlertMonitoring/Index\"", html);
    }

    [TestMethod]
    public async Task CreatePageExposesApproversOnlyToAuthorizedEmployeesAndSupportsQueryPrefill()
    {
        using (var anonymous = await Http.GetAsync("/DependencyRequests/Create"))
        {
            Assert.AreEqual(HttpStatusCode.Redirect, anonymous.StatusCode);
            var body = await anonymous.Content.ReadAsStringAsync();
            Assert.DoesNotContain("admin@default.com", body);
        }

        var (email, password) = await RegisterAndLoginAsync();
        using (var unprivileged = await Http.GetAsync("/DependencyRequests/Create"))
        {
            AssertRedirect(unprivileged, "/Error/Code403", exact: false);
        }

        await GrantPermissionsAndReloginAsync(email, password, AppPermissionNames.CanSubmitDependencyRequests);

        var url = "/DependencyRequests/Create?ecosystem=npm&source=https://registry.npmjs.org/&package=dompurify@3.2.8&project=AlertCenter";
        using var response = await Http.GetAsync(url);
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();

        StringAssert.Contains(html, "Who can approve your request");
        StringAssert.Contains(html, "mailto:admin@default.com");
        StringAssert.Contains(html, "dompurify@3.2.8");
        StringAssert.Contains(html, "value=\"AlertCenter\"");
        Assert.IsTrue(Regex.IsMatch(html, @"<option\s+value=""npm""\s+selected=""selected""", RegexOptions.IgnoreCase),
            "Expected npm ecosystem option to be pre-selected.");
        StringAssert.Contains(html, "<aside class=\"s360-concept-rail\"");
        StringAssert.Contains(html, "Understand your request");
    }

    [TestMethod]
    public async Task RequestDetailsShowsStepperApproversCopyNudgeAndReviewerDirectLink()
    {
        var (employeeEmail, _) = await RegisterAndLoginAsync();
        int employeeRequestId = 0;
        int adminRequestId = 0;

        try
        {
            using (var scope = Server!.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var employee = await db.Users.SingleAsync(u => u.Email == employeeEmail);
                var admin = await db.Users.SingleAsync(u => u.Email == "admin@default.com");

                var employeeApp = new DependencyApplication
                {
                    RequestedByUserId = employee.Id,
                    Ecosystem = "npm",
                    Source = "https://registry.npmjs.org/",
                    DirectPackages = JsonSerializer.Serialize(new[] { new { Name = "dompurify", Version = "3.2.8" } }),
                    Justification = "Needed for safe HTML rendering",
                    Project = "AlertCenter",
                    ResolutionContext = "npm",
                    Status = ApplicationStatus.ReadyForReview
                };
                var adminApp = new DependencyApplication
                {
                    RequestedByUserId = admin.Id,
                    Ecosystem = "nuget",
                    Source = "https://api.nuget.org/v3/index.json",
                    DirectPackages = JsonSerializer.Serialize(new[] { new { Name = "Demo.Pkg", Version = "1.0.0" } }),
                    Justification = "Self request check",
                    Project = "S360",
                    ResolutionContext = "net10.0",
                    Status = ApplicationStatus.ReadyForReview
                };
                db.DependencyApplications.AddRange(employeeApp, adminApp);
                await db.SaveChangesAsync();
                employeeRequestId = employeeApp.Id;
                adminRequestId = adminApp.Id;
            }

            // As employee (owner, non-reviewer): sees stepper, approver directory, copy nudge, no review CTA.
            using (var ownerView = await Http.GetAsync($"/DependencyRequests/Details/{employeeRequestId}"))
            {
                ownerView.EnsureSuccessStatusCode();
                var html = await ownerView.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "s360-stepper");
                StringAssert.Contains(html, "Next step: contact an approver");
                StringAssert.Contains(html, "mailto:admin@default.com");
                StringAssert.Contains(html, "data-copy-nudge");
                StringAssert.Contains(html, "/js/request-nudge.js");
                StringAssert.Contains(html, $"#request-{employeeRequestId}");
                StringAssert.Contains(html, "dompurify@3.2.8");
                Assert.DoesNotContain("Review this request", html);
            }

            // Log in as admin (approver).
            await LoginAsAdmin();

            // Reviewing another employee's request shows direct "Review this request" CTA pointing to #request-{id}.
            using (var reviewerView = await Http.GetAsync($"/DependencyRequests/Details/{employeeRequestId}"))
            {
                reviewerView.EnsureSuccessStatusCode();
                var html = await reviewerView.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "Review this request");
                StringAssert.Contains(html, $"/DependencyReviews?filter=pending#request-{employeeRequestId}");
            }

            // Viewing own request as approver shows self-approval warning instead of direct CTA.
            using (var selfView = await Http.GetAsync($"/DependencyRequests/Details/{adminRequestId}"))
            {
                selfView.EnsureSuccessStatusCode();
                var html = await selfView.Content.ReadAsStringAsync();
                StringAssert.Contains(html, "You — cannot self-approve");
                StringAssert.Contains(html, "Applicants cannot approve their own requests.");
                Assert.DoesNotContain("Review this request", html);
            }

            // Approvals page renders the target anchor id="request-{id}".
            using (var reviewQueue = await Http.GetAsync("/DependencyReviews/Index?filter=pending"))
            {
                reviewQueue.EnsureSuccessStatusCode();
                var html = await reviewQueue.Content.ReadAsStringAsync();
                StringAssert.Contains(html, $"id=\"request-{employeeRequestId}\"");
                StringAssert.Contains(html, "s360-review-card");
            }
        }
        finally
        {
            if (employeeRequestId > 0 || adminRequestId > 0)
            {
                using var scope = Server!.Services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
                var toRemove = await db.DependencyApplications
                    .Where(a => a.Id == employeeRequestId || a.Id == adminRequestId)
                    .ToListAsync();
                db.DependencyApplications.RemoveRange(toRemove);
                await db.SaveChangesAsync();
            }
        }
    }

    [TestMethod]
    public async Task FreshVulnerabilityAuditRendersCompactMetadataInsteadOfSyncAlertBanner()
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<TemplateDbContext>();
            var now = DateTime.UtcNow;
            var state = await db.VulnerabilitySyncStates.FirstOrDefaultAsync();
            if (state == null)
            {
                state = new VulnerabilitySyncState();
                db.VulnerabilitySyncStates.Add(state);
            }
            state.LastAttemptAtUtc = now;
            state.LastSuccessfulAttemptAtUtc = now;
            state.LastSuccessAtUtc = now;
            state.LastError = null;
            await db.SaveChangesAsync();
        }

        await LoginAsAdmin();
        var probePackage = "fresh-sync-probe-" + Guid.NewGuid().ToString("N");
        using var response = await Http.GetAsync($"/VulnerabilityAudit/Index?ecosystem=nuget&package={probePackage}");
        response.EnsureSuccessStatusCode();
        var html = await response.Content.ReadAsStringAsync();
        StringAssert.Contains(html, "<p class=\"s360-sync-meta");
        StringAssert.Contains(html, "Last successful sync");
        Assert.DoesNotContain("Audit data is stale", html);
    }

    private async Task GrantPermissionsAndReloginAsync(string email, string password, params string[] permissions)
    {
        using (var scope = Server!.Services.CreateScope())
        {
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var roleName = "Employee-" + Guid.NewGuid().ToString("N");
            var role = new IdentityRole(roleName);
            Assert.IsTrue((await roleManager.CreateAsync(role)).Succeeded);
            foreach (var permission in permissions)
            {
                Assert.IsTrue((await roleManager.AddClaimAsync(role, new Claim(AppPermissions.Type, permission))).Succeeded);
            }
            var user = await userManager.FindByEmailAsync(email);
            Assert.IsNotNull(user);
            Assert.IsTrue((await userManager.AddToRoleAsync(user, roleName)).Succeeded);
        }

        var loginResponse = await PostForm("/Account/Login", new Dictionary<string, string>
        {
            { "EmailOrUserName", email },
            { "Password", password }
        });
        Assert.AreEqual(HttpStatusCode.Found, loginResponse.StatusCode);
    }

    private static void AssertSidebarItemActive(string html, string groupLabel, bool expectedActive)
    {
        var pattern = $@"<li class=""sidebar-item(?<active>\s+active)?\s*"">(?:(?!<li\b)[\s\S])*?<span class=""align-middle"">{Regex.Escape(groupLabel)}</span>";
        var match = Regex.Match(html, pattern, RegexOptions.Singleline);
        Assert.IsTrue(match.Success, $"Could not find sidebar group '{groupLabel}'.");
        Assert.AreEqual(expectedActive, match.Groups["active"].Success,
            $"Sidebar group '{groupLabel}' expected active={expectedActive}, actual={match.Groups["active"].Success}.");
    }
}
