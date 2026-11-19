namespace ApiVault.Core.Entities;

public class SecretVersion
{
    public Guid Id { get; set; }
    public Guid SecretId { get; set; }
    public byte[] EncryptedPayload { get; set; } = [];
    public byte[] Nonce { get; set; } = [];
    public byte[] AuthTag { get; set; } = [];
    public int EncryptionVersion { get; set; } = 1;
    public DateTime CreatedAt { get; set; }
    public Secret? Secret { get; set; }
}
