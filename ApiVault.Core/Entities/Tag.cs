namespace ApiVault.Core.Entities;

public class Tag
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public ICollection<SecretTagMapping> SecretMappings { get; set; } = new List<SecretTagMapping>();
}

public class SecretTagMapping
{
    public Guid SecretId { get; set; }
    public Guid TagId { get; set; }
    public Secret? Secret { get; set; }
    public Tag? Tag { get; set; }
}
