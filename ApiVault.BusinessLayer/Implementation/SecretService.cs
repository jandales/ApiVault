using ApiVault.BusinessLayer.Validators;
using ApiVault.Core.Constants;
using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;

namespace ApiVault.BusinessLayer.Implementation;

public class SecretService(ISecretRepository secrets, IVaultRepository vaults, ITagRepository tags) : ISecretService
{
    public async Task<ServiceResult<SecretResponse>> CreateAsync(string userId, CreateSecretRequest r)
    {
        var errors = SecretValidator.ValidateCreate(r);
        if (errors.Count > 0) return ServiceResult<SecretResponse>.Fail(ErrorKind.Validation, "Invalid secret.", errors);

        // The vault must belong to the caller; an unknown and a foreign vault look the same.
        if (await vaults.GetOwnedAsync(r.VaultId, userId) is null)
            return ServiceResult<SecretResponse>.Fail(ErrorKind.NotFound, "Vault not found.");
        if (await secrets.ExistsAsync(r.Id))
            return ServiceResult<SecretResponse>.Fail(ErrorKind.Conflict, "A secret with this id already exists.");

        var tagEntities = await ResolveTagsAsync(userId, r.TagIds);
        if (tagEntities is null) return ServiceResult<SecretResponse>.Fail(ErrorKind.Validation, "One or more tags were not found.");

        var secret = new Secret
        {
            Id = r.Id,
            VaultId = r.VaultId,
            Name = r.Name.Trim(),
            Description = Clean(r.Description),
            SecretType = r.SecretType,
            Provider = Clean(r.Provider),
            Environment = Clean(r.Environment),
            EncryptedPayload = r.EncryptedPayload,
            Nonce = r.Nonce,
            AuthTag = r.AuthTag,
            EncryptionVersion = r.EncryptionVersion,
            ExpiresAt = ToUtc(r.ExpiresAt),
            CreatedAt = DateTime.UtcNow,
        };
        foreach (var t in tagEntities) secret.TagMappings.Add(new SecretTagMapping { SecretId = secret.Id, TagId = t.Id, Tag = t });

        secrets.Add(secret);
        await secrets.SaveChangesAsync();
        return ServiceResult<SecretResponse>.Ok(ToResponse(secret));
    }

    public async Task<PagedResult<SecretSummary>> ListAsync(string userId, SecretQuery query)
    {
        query.Page = Math.Max(1, query.Page);
        query.PageSize = Math.Clamp(query.PageSize, 1, SecretLimits.MaxPageSize);
        var (items, total) = await secrets.QueryAsync(userId, query);
        return new PagedResult<SecretSummary>(items.Select(ToSummary).ToList(), query.Page, query.PageSize, total);
    }

    public async Task<ServiceResult<SecretResponse>> GetAsync(string userId, Guid secretId)
    {
        var secret = await secrets.GetOwnedAsync(secretId, userId);
        return secret is null ? NotFound<SecretResponse>() : ServiceResult<SecretResponse>.Ok(ToResponse(secret));
    }

    public async Task<ServiceResult<SecretResponse>> UpdateAsync(string userId, Guid secretId, UpdateSecretRequest r)
    {
        var errors = SecretValidator.ValidateUpdate(r);
        if (errors.Count > 0) return ServiceResult<SecretResponse>.Fail(ErrorKind.Validation, "Invalid secret.", errors);

        var secret = await secrets.GetOwnedAsync(secretId, userId);
        if (secret is null) return NotFound<SecretResponse>();

        var tagEntities = await ResolveTagsAsync(userId, r.TagIds);
        if (tagEntities is null) return ServiceResult<SecretResponse>.Fail(ErrorKind.Validation, "One or more tags were not found.");

        secret.Name = r.Name.Trim();
        secret.Description = Clean(r.Description);
        secret.SecretType = r.SecretType;
        secret.Provider = Clean(r.Provider);
        secret.Environment = Clean(r.Environment);
        secret.ExpiresAt = ToUtc(r.ExpiresAt);
        secret.ModifiedAt = DateTime.UtcNow;
        ReplaceTags(secret, tagEntities);

        if (r.EncryptedPayload is not null)
            ReplacePayload(secret, r.EncryptedPayload, r.Nonce!, r.AuthTag!, r.EncryptionVersion!.Value);

        await secrets.SaveChangesAsync(); // metadata, tags, version snapshot and new payload: one transaction
        return ServiceResult<SecretResponse>.Ok(ToResponse(secret));
    }

    public async Task<ServiceResult<bool>> DeleteAsync(string userId, Guid secretId)
    {
        var secret = await secrets.GetOwnedAsync(secretId, userId);
        if (secret is null) return NotFound<bool>();
        secrets.Remove(secret); // permanent: cascades to versions and tag mappings
        await secrets.SaveChangesAsync();
        return ServiceResult<bool>.Ok(true);
    }

    public async Task<ServiceResult<SecretResponse>> SetArchivedAsync(string userId, Guid secretId, bool archived)
    {
        var secret = await secrets.GetOwnedAsync(secretId, userId);
        if (secret is null) return NotFound<SecretResponse>();
        if (secret.IsArchived != archived)
        {
            secret.IsArchived = archived;
            secret.ModifiedAt = DateTime.UtcNow;
            await secrets.SaveChangesAsync();
        }
        return ServiceResult<SecretResponse>.Ok(ToResponse(secret));
    }

    public async Task<ServiceResult<IReadOnlyList<SecretVersionResponse>>> GetVersionsAsync(string userId, Guid secretId)
    {
        if (await secrets.GetOwnedAsync(secretId, userId) is null) return NotFound<IReadOnlyList<SecretVersionResponse>>();
        var versions = await secrets.GetVersionsAsync(secretId);
        return ServiceResult<IReadOnlyList<SecretVersionResponse>>.Ok(versions
            .Select(v => new SecretVersionResponse(v.Id, v.SecretId, v.EncryptedPayload, v.Nonce, v.AuthTag, v.EncryptionVersion, v.CreatedAt))
            .ToList());
    }

    /// <summary>Replaces only the encrypted payload (e.g. a rotated token); the previous payload becomes a version.</summary>
    public async Task<ServiceResult<SecretResponse>> CreateVersionAsync(string userId, Guid secretId, CreateSecretVersionRequest r)
    {
        var errors = SecretValidator.ValidateVersion(r);
        if (errors.Count > 0) return ServiceResult<SecretResponse>.Fail(ErrorKind.Validation, "Invalid secret version.", errors);

        var secret = await secrets.GetOwnedAsync(secretId, userId);
        if (secret is null) return NotFound<SecretResponse>();

        ReplacePayload(secret, r.EncryptedPayload, r.Nonce, r.AuthTag, r.EncryptionVersion);
        secret.ModifiedAt = DateTime.UtcNow;
        await secrets.SaveChangesAsync();
        return ServiceResult<SecretResponse>.Ok(ToResponse(secret));
    }

    private void ReplacePayload(Secret secret, byte[] payload, byte[] nonce, byte[] tag, int version)
    {
        secrets.AddVersion(new SecretVersion
        {
            Id = Guid.NewGuid(),
            SecretId = secret.Id,
            EncryptedPayload = secret.EncryptedPayload,
            Nonce = secret.Nonce,
            AuthTag = secret.AuthTag,
            EncryptionVersion = secret.EncryptionVersion,
            CreatedAt = DateTime.UtcNow,
        });
        secret.EncryptedPayload = payload;
        secret.Nonce = nonce;
        secret.AuthTag = tag;
        secret.EncryptionVersion = version;
    }

    private static void ReplaceTags(Secret secret, IReadOnlyList<Tag> wanted)
    {
        var wantedIds = wanted.Select(t => t.Id).ToHashSet();
        foreach (var m in secret.TagMappings.Where(m => !wantedIds.Contains(m.TagId)).ToList())
            secret.TagMappings.Remove(m);
        var existing = secret.TagMappings.Select(m => m.TagId).ToHashSet();
        foreach (var t in wanted.Where(t => !existing.Contains(t.Id)))
            secret.TagMappings.Add(new SecretTagMapping { SecretId = secret.Id, TagId = t.Id, Tag = t });
    }

    /// <summary>Returns null if any requested tag is missing or belongs to another user.</summary>
    private async Task<IReadOnlyList<Tag>?> ResolveTagsAsync(string userId, IReadOnlyList<Guid>? tagIds)
    {
        var ids = (tagIds ?? []).Distinct().ToList();
        if (ids.Count == 0) return [];
        var owned = await tags.GetOwnedManyAsync(ids, userId);
        return owned.Count == ids.Count ? owned : null;
    }

    private static string? Clean(string? v) => string.IsNullOrWhiteSpace(v) ? null : v.Trim();

    private static DateTime? ToUtc(DateTime? v) => v switch
    {
        null => null,
        { Kind: DateTimeKind.Utc } d => d,
        { Kind: DateTimeKind.Local } d => d.ToUniversalTime(),
        var d => DateTime.SpecifyKind(d.Value, DateTimeKind.Utc),
    };

    private static ServiceResult<T> NotFound<T>() => ServiceResult<T>.Fail(ErrorKind.NotFound, "Secret not found.");

    private static IReadOnlyList<TagDto> Tags(Secret s) =>
        s.TagMappings.Where(m => m.Tag is not null).Select(m => new TagDto(m.TagId, m.Tag!.Name)).OrderBy(t => t.Name).ToList();

    private static SecretSummary ToSummary(Secret s) => new(s.Id, s.VaultId, s.Name, s.Description, s.SecretType, s.Provider,
        s.Environment, s.ExpiresAt, s.CreatedAt, s.ModifiedAt, s.IsArchived, Tags(s));

    private static SecretResponse ToResponse(Secret s) => new(s.Id, s.VaultId, s.Name, s.Description, s.SecretType, s.Provider,
        s.Environment, s.ExpiresAt, s.CreatedAt, s.ModifiedAt, s.IsArchived, Tags(s),
        s.EncryptedPayload, s.Nonce, s.AuthTag, s.EncryptionVersion);
}
