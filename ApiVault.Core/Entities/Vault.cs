namespace ApiVault.Core.Entities;

public class Vault
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string KdfAlgorithm { get; set; } = "Argon2id";
    public byte[] KdfSalt { get; set; } = [];
    public string KdfParameters { get; set; } = string.Empty;
    public string EncryptionAlgorithm { get; set; } = "AES-256-GCM";
    public int KeyVersion { get; set; } = 1;
    public DateTime CreatedAt { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public ICollection<Secret> Secrets { get; set; } = new List<Secret>();
    public ICollection<VaultKeyWrapper> KeyWrappers { get; set; } = new List<VaultKeyWrapper>();
}
