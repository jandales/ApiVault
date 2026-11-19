namespace ApiVault.Core.Entities;

public class VaultKeyWrapper
{
    public Guid Id { get; set; }
    public Guid VaultId { get; set; }
    /// <summary>Password or Recovery.</summary>
    public string WrapperType { get; set; } = string.Empty;
    public byte[] EncryptedVaultKey { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];
    public int KeyVersion { get; set; } = 1;
    public DateTime CreatedAt { get; set; }
    public Vault? Vault { get; set; }
}
