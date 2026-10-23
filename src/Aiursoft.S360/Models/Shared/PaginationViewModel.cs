namespace Aiursoft.S360.Models.Shared;

public record PaginationViewModel(int Page, int PageSize, int Total,
    string PageParameter = "page", string? Fragment = null)
{
    public int PageCount => Math.Max(1, (Total + PageSize - 1) / PageSize);
}
