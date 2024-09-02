using System.ComponentModel.DataAnnotations;

namespace API.Dtos.Role
{
    public class CreateRoleDto
    {
        [Required(ErrorMessage ="Role Name is required.")]
        public string RoleName { get; set; } = null!;
    }
}