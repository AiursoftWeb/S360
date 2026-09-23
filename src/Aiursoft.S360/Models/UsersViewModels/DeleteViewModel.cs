using System.ComponentModel.DataAnnotations;
using Aiursoft.S360.Entities;
using Aiursoft.UiStack.Layout;

namespace Aiursoft.S360.Models.UsersViewModels;

public class DeleteViewModel : UiStackLayoutViewModel
{
    public DeleteViewModel()
    {
        PageTitle = "Delete User";
    }

    [Display(Name = "User")]
    public required User User { get; set; }
}
