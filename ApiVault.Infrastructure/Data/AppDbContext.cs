using ApiVault.Core.Entities;
using ApiVault.Infrastructure.Identity;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ApiVault.Infrastructure.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<ApplicationUser>(options), IDataProtectionKeyContext
{
    /// <summary>ASP.NET Data Protection keys (email/reset tokens, Google sign-in cookies), so they survive redeploys.</summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    public DbSet<Vault> Vaults => Set<Vault>();
    public DbSet<VaultKeyWrapper> VaultKeyWrappers => Set<VaultKeyWrapper>();
    public DbSet<Secret> Secrets => Set<Secret>();
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();
    public DbSet<Tag> Tags => Set<Tag>();
    public DbSet<SecretTagMapping> SecretTagMappings => Set<SecretTagMapping>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
    }
}
