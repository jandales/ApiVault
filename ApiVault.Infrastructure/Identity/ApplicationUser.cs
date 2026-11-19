using Microsoft.AspNetCore.Identity;

namespace ApiVault.Infrastructure.Identity;

public class ApplicationUser : IdentityUser
{
    public DateTime CreatedAt { get; set; }
}
