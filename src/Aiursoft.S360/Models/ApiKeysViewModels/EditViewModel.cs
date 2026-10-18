using System.ComponentModel.DataAnnotations;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.ApiKeysViewModels;

public class EditViewModel : UiStackLayoutViewModel
{
    public EditViewModel() => PageTitle = "API Key";
    public Guid? Id { get; set; }
    [Required, StringLength(100)] public string Name { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public bool CanPublishBaselines { get; set; }
    public DateTime ExpirationTime { get; set; } = DateTime.UtcNow.AddYears(1);
}
