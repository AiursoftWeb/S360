using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.SupplyChainViewModels;
using Aiursoft.S360.Services;
using Aiursoft.S360.SDK;
using Aiursoft.UiStack.Navigation;
using Aiursoft.WebTools.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Aiursoft.S360.Controllers;

[Authorize(Policy = AppPermissionNames.CanReadSupplyChain)]
[LimitPerMin]
public class BuildChecksController(TemplateDbContext db) : Controller
{
    [RenderInNavBar(NavGroupName = "Supply chain", NavGroupOrder = 10,
        CascadedLinksGroupName = "Security audit", CascadedLinksIcon = "shield-check", CascadedLinksOrder = 3,
        LinkText = "Build check records", LinkOrder = 2)]
    public async Task<IActionResult> Index(string? project = null, int page = 1, int? checkId = null)
    {
        if (page is < 1 or > 10000 || project?.Length > 200 || checkId is <= 0) return BadRequest();
        project = project?.Trim();
        var query = db.BuildChecks.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(project)) query = query.Where(c => c.Project != null && c.Project.Contains(project));
        if (checkId != null) query = query.Where(c => c.Id == checkId);
        var model = new BuildChecksViewModel
        {
            Project = project,
            Page = page,
            Total = await query.CountAsync(),
            Checks = await query.Include(c => c.Dependencies)
                .OrderByDescending(c => c.CreatedAtUtc).ThenByDescending(c => c.Id)
                .Skip((page - 1) * 50).Take(50).ToListAsync()
        };
        var runIds = model.Checks.Select(c => c.RunId).Distinct().ToList();
        var batches = await db.BuildChecks.AsNoTracking().Where(c => runIds.Contains(c.RunId)).ToListAsync();
        model.RunStatuses = batches.GroupBy(c => c.RunId).ToDictionary(g => g.Key, g =>
        {
            var complete = BuildCheckRun.IsComplete(g.ToList());
            return new BuildRunStatus(complete, complete && g.All(c => c.Trusted));
        });
        var blocks = await db.BlockRules.AsNoTracking().Where(b => b.Active).ToListAsync();
        foreach (var dependency in model.Checks.SelectMany(c => c.Dependencies))
        {
            var block = blocks.FirstOrDefault(b => b.Ecosystem == dependency.Ecosystem &&
                TrustPattern.Matches(b.PackagePattern, dependency.Name, dependency.Ecosystem) &&
                TrustPattern.VersionMatches(b.Version, dependency.Version, dependency.Ecosystem, true));
            if (block != null) model.CurrentBlockReasons[dependency.Id] = $"{block.PackagePattern} @ {block.Version}: {block.Reason}";
        }
        return this.StackView(model);
    }
}
