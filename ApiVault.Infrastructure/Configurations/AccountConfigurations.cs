using ApiVault.Core.Entities;
using ApiVault.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ApiVault.Infrastructure.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> b)
    {
        b.ToTable("RefreshTokens");
        b.HasKey(t => t.Id);
        b.Property(t => t.UserId).HasMaxLength(450).IsRequired();
        b.Property(t => t.TokenHash).HasMaxLength(256).IsRequired();
        b.HasIndex(t => new { t.UserId, t.ExpiresAt });
        b.HasIndex(t => t.TokenHash).IsUnique();
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class NotificationConfiguration : IEntityTypeConfiguration<Notification>
{
    public void Configure(EntityTypeBuilder<Notification> b)
    {
        b.ToTable("Notifications");
        b.HasKey(n => n.Id);
        b.Property(n => n.UserId).HasMaxLength(450).IsRequired();
        b.Property(n => n.Title).HasMaxLength(200).IsRequired();
        b.Property(n => n.Message).HasMaxLength(500).IsRequired();
        b.Property(n => n.NotificationType).HasMaxLength(50).IsRequired();
        b.HasIndex(n => new { n.UserId, n.IsRead });
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(n => n.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class SecurityEventConfiguration : IEntityTypeConfiguration<SecurityEvent>
{
    public void Configure(EntityTypeBuilder<SecurityEvent> b)
    {
        b.ToTable("SecurityEvents");
        b.HasKey(e => e.Id);
        b.Property(e => e.UserId).HasMaxLength(450).IsRequired();
        b.Property(e => e.EventType).HasMaxLength(100).IsRequired();
        b.Property(e => e.IpAddress).HasMaxLength(45);
        b.Property(e => e.UserAgent).HasMaxLength(500);
        b.HasIndex(e => new { e.UserId, e.CreatedAt });
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(e => e.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}
