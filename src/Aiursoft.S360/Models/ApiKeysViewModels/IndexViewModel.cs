using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.ApiKeysViewModels;

public class IndexViewModel : UiStackLayoutViewModel
{
    public IndexViewModel() => PageTitle = "API Keys";
    public List<ApiKey> ApiKeys { get; set; } = [];
    public string? NewKey { get; set; }
}
