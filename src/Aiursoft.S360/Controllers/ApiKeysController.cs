using System.Security.Cryptography;
using System.Security.Claims;
using Aiursoft.S360.Authorization;
using Aiursoft.S360.Entities;
using Aiursoft.S360.Models.ApiKeysViewModels;
using Aiursoft.S360.Services.Authentication;
using Aiursoft.S360.Services;
using Aiursoft.UiStack.Navigation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Localization;

namespace Aiursoft.S360.Controllers;

[Authorize(Policy = AppPermissionNames.CanManageApiKeys)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public class ApiKeysController(TemplateDbContext db, ApiKeyPermissions permissions,
    IStringLocalizer<ApiKeysController> localizer) : Controller
{
    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier)!;
    private Task<bool> CanManage() => permissions.HasAsync(UserId, AppPermissionNames.CanManageApiKeys);

    [RenderInNavBar(NavGroupName = "Settings", NavGroupOrder = 9998,
        CascadedLinksGroupName = "Personal", CascadedLinksIcon = "user", CascadedLinksOrder = 1,
        LinkText = "API Keys", LinkOrder = 2)]
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        if (!await CanManage()) return Forbid();
        return this.StackView(new IndexViewModel
        {
            ApiKeys = await db.ApiKeys.AsNoTracking().Where(k => k.UserId == UserId)
                .OrderByDescending(k => k.CreatedAt).ToListAsync(),
            NewKey = TempData["NewKey"] as string
        });
    }

    [HttpGet]
    public async Task<IActionResult> Create()
    {
        if (!await CanManage()) return Forbid();
        return this.StackView(new EditViewModel(), "Edit");
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(EditViewModel model)
    {
        if (!await CanManage()) return Forbid();
        if (model.Id.HasValue) return BadRequest();
        if (model.CanPublishBaselines && !await permissions.HasAsync(UserId, AppPermissionNames.CanPublishBaselines))
            return Forbid();
        Validate(model);
        if (!ModelState.IsValid) return this.StackView(model, "Edit");
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        db.ApiKeys.Add(new ApiKey
        {
            Name = model.Name.Trim(), UserId = UserId, IsEnabled = model.IsEnabled,
            CanPublishBaselines = model.CanPublishBaselines, ExpirationTime = model.ExpirationTime,
            SecretHash = ApiKeyPermissions.Hash(secret)
        });
        await db.SaveChangesAsync();
        TempData["NewKey"] = secret;
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Edit(Guid id)
    {
        if (!await CanManage()) return Forbid();
        var key = await db.ApiKeys.AsNoTracking().SingleOrDefaultAsync(k => k.Id == id && k.UserId == UserId);
        if (key == null) return NotFound();
        return this.StackView(new EditViewModel
        {
            Id = key.Id, Name = key.Name, IsEnabled = key.IsEnabled,
            CanPublishBaselines = key.CanPublishBaselines, ExpirationTime = key.ExpirationTime
        });
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(EditViewModel model)
    {
        if (!await CanManage()) return Forbid();
        var key = await db.ApiKeys.SingleOrDefaultAsync(k => k.Id == model.Id && k.UserId == UserId);
        if (key == null) return NotFound();
        if (model.CanPublishBaselines && !await permissions.HasAsync(UserId, AppPermissionNames.CanPublishBaselines))
            return Forbid();
        Validate(model);
        if (!ModelState.IsValid) return this.StackView(model);
        key.Name = model.Name.Trim();
        key.IsEnabled = model.IsEnabled;
        key.CanPublishBaselines = model.CanPublishBaselines;
        key.ExpirationTime = model.ExpirationTime;
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    [HttpPost, ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id)
    {
        if (!await CanManage()) return Forbid();
        var key = await db.ApiKeys.SingleOrDefaultAsync(k => k.Id == id && k.UserId == UserId);
        if (key == null) return NotFound();
        db.ApiKeys.Remove(key);
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    private void Validate(EditViewModel model)
    {
        if (model.ExpirationTime <= DateTime.UtcNow)
            ModelState.AddModelError(nameof(model.ExpirationTime), localizer["Expiration must be in the future."]);
    }
}
