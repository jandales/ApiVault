using ApiVault.Core.Entities;
using ApiVault.Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ApiVault.Infrastructure.Configurations;

public class VaultConfiguration : IEntityTypeConfiguration<Vault>
{
    public void Configure(EntityTypeBuilder<Vault> b)
    {
        b.ToTable("Vaults");
        b.HasKey(v => v.Id);
        b.Property(v => v.UserId).HasMaxLength(450).IsRequired();
        b.Property(v => v.Name).HasMaxLength(150).IsRequired();
        b.Property(v => v.Description).HasMaxLength(500);
        b.Property(v => v.KdfAlgorithm).HasMaxLength(30).IsRequired();
        b.Property(v => v.KdfSalt).HasMaxLength(64).IsRequired();
        b.Property(v => v.KdfParameters).HasMaxLength(500).IsRequired();
        b.Property(v => v.EncryptionAlgorithm).HasMaxLength(30).IsRequired();
        b.HasIndex(v => v.UserId).IsUnique(); // single-vault model: one vault per account
        // Deliberate: deleting a user never silently cascades into encrypted vaults.
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(v => v.UserId).OnDelete(DeleteBehavior.Restrict);
    }
}

public class VaultKeyWrapperConfiguration : IEntityTypeConfiguration<VaultKeyWrapper>
{
    public void Configure(EntityTypeBuilder<VaultKeyWrapper> b)
    {
        b.ToTable("VaultKeyWrappers");
        b.HasKey(w => w.Id);
        b.Property(w => w.WrapperType).HasMaxLength(30).IsRequired();
        b.Property(w => w.EncryptedVaultKey).IsRequired();
        b.Property(w => w.Nonce).HasMaxLength(12).IsRequired();
        b.Property(w => w.AuthTag).HasMaxLength(16).IsRequired();
        // Lifecycle rule: at most one active wrapper per type; rotating replaces it.
        b.HasIndex(w => new { w.VaultId, w.WrapperType }).IsUnique();
        b.HasOne(w => w.Vault).WithMany(v => v.KeyWrappers).HasForeignKey(w => w.VaultId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class SecretConfiguration : IEntityTypeConfiguration<Secret>
{
    public void Configure(EntityTypeBuilder<Secret> b)
    {
        b.ToTable("Secrets");
        b.HasKey(s => s.Id);
        b.Property(s => s.Name).HasMaxLength(200).IsRequired();
        b.Property(s => s.Description).HasMaxLength(500);
        b.Property(s => s.SecretType).HasMaxLength(50).IsRequired();
        b.Property(s => s.Provider).HasMaxLength(150);
        b.Property(s => s.Environment).HasMaxLength(30);
        b.Property(s => s.EncryptedPayload).IsRequired();
        b.Property(s => s.Nonce).HasMaxLength(12).IsRequired();
        b.Property(s => s.AuthTag).HasMaxLength(16).IsRequired();
        b.HasIndex(s => new { s.VaultId, s.CreatedAt });
        b.HasIndex(s => new { s.VaultId, s.SecretType });
        b.HasIndex(s => new { s.VaultId, s.ExpiresAt });
        b.HasOne(s => s.Vault).WithMany(v => v.Secrets).HasForeignKey(s => s.VaultId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class SecretVersionConfiguration : IEntityTypeConfiguration<SecretVersion>
{
    public void Configure(EntityTypeBuilder<SecretVersion> b)
    {
        b.ToTable("SecretVersions");
        b.HasKey(s => s.Id);
        b.Property(s => s.EncryptedPayload).IsRequired();
        b.Property(s => s.Nonce).HasMaxLength(12).IsRequired();
        b.Property(s => s.AuthTag).HasMaxLength(16).IsRequired();
        b.HasIndex(s => new { s.SecretId, s.CreatedAt });
        b.HasOne(s => s.Secret).WithMany(s => s.Versions).HasForeignKey(s => s.SecretId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class TagConfiguration : IEntityTypeConfiguration<Tag>
{
    public void Configure(EntityTypeBuilder<Tag> b)
    {
        b.ToTable("Tags");
        b.HasKey(t => t.Id);
        b.Property(t => t.UserId).HasMaxLength(450).IsRequired();
        b.Property(t => t.Name).HasMaxLength(100).IsRequired();
        b.HasIndex(t => new { t.UserId, t.Name }).IsUnique();
        b.HasOne<ApplicationUser>().WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.Cascade);
    }
}

public class SecretTagMappingConfiguration : IEntityTypeConfiguration<SecretTagMapping>
{
    public void Configure(EntityTypeBuilder<SecretTagMapping> b)
    {
        b.ToTable("SecretTagMappings");
        b.HasKey(m => new { m.SecretId, m.TagId });
        b.HasOne(m => m.Secret).WithMany(s => s.TagMappings).HasForeignKey(m => m.SecretId).OnDelete(DeleteBehavior.Cascade);
        // NoAction avoids SQL Server multiple-cascade-path errors; tag deletion removes mappings in the service.
        b.HasOne(m => m.Tag).WithMany(t => t.SecretMappings).HasForeignKey(m => m.TagId).OnDelete(DeleteBehavior.NoAction);
    }
}
