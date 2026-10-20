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
        if (string.IsNullOrWhiteSpace(project) || project.Length > 750) return BadRequest();
        return await VulnerabilityAuditSnapshot.ExecuteAsync(db, async () =>
        {
            var model = new InventoryViewModel
            {
                Tab = "projects", Scope = "baseline",
                Project = project.Contains("//", StringComparison.Ordinal) ? project : null,
                Repository = project.Contains("//", StringComparison.Ordinal) ? null : project
            };
            await inventory.PopulateAsync(model, projectOnly: true);
            var result = model.Summary;
            var (message, color) = result switch
            {
                { ProjectCount: 0 } => ("unknown", "9f9f9f"),
                { VulnerableProjectCount: > 0 } => ("CVE found", "e05d44"),
                {} p when p.ProjectStatuses.GetValueOrDefault(InventoryStatus.NonCompliant) > 0 => ("non-compliant", "e05d44"),
                {} p when p.ProjectStatuses.GetValueOrDefault(InventoryStatus.Pending) > 0 => ("pending", "dfb317"),
                _ => ("compliant", "4c1")
            };
            var messageWidth = message switch
            {
                "compliant" => 65,
                "CVE found" => 68,
                "non-compliant" => 90,
                "pending" => 55,
                _ => 60
            };
            const int labelWidth = 38;
            var width = labelWidth + messageWidth;
            var messageX = (labelWidth * 2 + messageWidth) * 5;
            var messageLength = (messageWidth - 10) * 10;
            // Fixed server text only. Match the standard Shields flat geometry and typography.
            return Content($"""
                <svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="S360: {message}">
                  <title>S360: {message}</title>
                  <linearGradient id="s" x2="0" y2="100%">
                    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
                    <stop offset="1" stop-opacity=".1"/>
                  </linearGradient>
                  <clipPath id="r"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath>
                  <g clip-path="url(#r)">
                    <rect width="{labelWidth}" height="20" fill="#555"/>
                    <rect x="{labelWidth}" width="{messageWidth}" height="20" fill="#{color}"/>
                    <rect width="{width}" height="20" fill="url(#s)"/>
                  </g>
                  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
                    <text aria-hidden="true" x="190" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="280">S360</text>
                    <text x="190" y="140" transform="scale(.1)" textLength="280">S360</text>
                    <text aria-hidden="true" x="{messageX}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{messageLength}">{message}</text>
                    <text x="{messageX}" y="140" transform="scale(.1)" textLength="{messageLength}">{message}</text>
                  </g>
                </svg>
                """, "image/svg+xml");
        });
    }
}
