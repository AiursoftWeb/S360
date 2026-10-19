using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.Vulnerability;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Aiursoft.S360.Controllers;

[AllowAnonymous]
public class BadgeController(TemplateDbContext db, CatalogInventoryService inventory) : Controller
{
    [HttpGet("badge.svg")]
    [ResponseCache(Duration = 60, Location = ResponseCacheLocation.Any)]
    public async Task<IActionResult> Project(string? project)
    {
        if (string.IsNullOrWhiteSpace(project) || project.Length > 200) return BadRequest();
        return await VulnerabilityAuditSnapshot.ExecuteAsync(db, async () =>
        {
            var model = new InventoryViewModel { Tab = "projects", Project = project, Scope = "baseline" };
            await inventory.PopulateAsync(model, projectOnly: true);
            var result = model.Projects.SingleOrDefault();
            var (message, color) = result switch
            {
                null => ("unknown", "64748b"),
                { } p when p.Versions.Any(v => v.Advisories.Count > 0) => ("CVE found", "dc2626"),
                { Status: InventoryStatus.NonCompliant } => ("non-compliant", "dc2626"),
                { Status: InventoryStatus.Pending } => ("pending", "a16207"),
                _ => ("compliant", "15803d")
            };
            // All SVG content is fixed server text; project names and report data are never embedded.
            return Content($"""
                <svg xmlns="http://www.w3.org/2000/svg" width="184" height="24" viewBox="0 0 184 24" role="img" aria-label="S360: {message}">
                  <title>S360: {message}</title>
                  <defs>
                    <linearGradient id="shine" x2="0" y2="1"><stop stop-color="#fff" stop-opacity=".12"/><stop offset="1" stop-opacity=".08"/></linearGradient>
                    <clipPath id="round"><rect width="184" height="24" rx="5"/></clipPath>
                  </defs>
                  <g clip-path="url(#round)">
                    <path fill="#1e293b" d="M0 0h72v24H0z"/>
                    <path fill="#{color}" d="M72 0h112v24H72z"/>
                    <path fill="url(#shine)" d="M0 0h184v24H0z"/>
                  </g>
                  <path fill="none" stroke="#a5f3fc" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" d="M14 5l6 2v5c0 3-3 5-6 7-3-2-6-4-6-7V7z M11 12l2 2 4-4"/>
                  <g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
                    <text x="46" y="16" font-weight="bold">S360</text>
                    <text x="128" y="16">{message}</text>
                  </g>
                </svg>
                """, "image/svg+xml");
        });
    }
}
