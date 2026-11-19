namespace ApiVault.Core.Entities;

public class Secret
{
    public Guid Id { get; set; }
    public Guid VaultId { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string SecretType { get; set; } = string.Empty;
    public string? Provider { get; set; }
    public string? Environment { get; set; }
    public byte[] EncryptedPayload { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];
    public int EncryptionVersion { get; set; } = 1;
    public DateTime? ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public bool IsArchived { get; set; }
    public Vault? Vault { get; set; }
    public ICollection<SecretVersion> Versions { get; set; } = new List<SecretVersion>();
    public ICollection<SecretTagMapping> TagMappings { get; set; } = new List<SecretTagMapping>();
}
