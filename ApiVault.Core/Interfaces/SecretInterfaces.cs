using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;

namespace ApiVault.Core.Interfaces;

public interface ISecretRepository
{
    Task<bool> ExistsAsync(Guid secretId, CancellationToken ct = default);
    /// <summary>Returns the secret (with tags) only if its vault belongs to <paramref name="userId"/>.</summary>
    Task<Secret?> GetOwnedAsync(Guid secretId, string userId, CancellationToken ct = default);
    Task<(IReadOnlyList<Secret> Items, int Total)> QueryAsync(string userId, SecretQuery query, CancellationToken ct = default);
    Task<IReadOnlyList<SecretVersion>> GetVersionsAsync(Guid secretId, CancellationToken ct = default);
    void Add(Secret secret);
    void AddVersion(SecretVersion version);
    void Remove(Secret secret);
    /// <summary>Persists all pending changes in a single transaction.</summary>
    Task SaveChangesAsync(CancellationToken ct = default);
}

public interface ITagRepository
{
    Task<IReadOnlyList<Tag>> ListAsync(string userId, CancellationToken ct = default);
    Task<Tag?> GetOwnedAsync(Guid tagId, string userId, CancellationToken ct = default);
    /// <summary>Returns only the tags among <paramref name="tagIds"/> that belong to <paramref name="userId"/>.</summary>
    Task<IReadOnlyList<Tag>> GetOwnedManyAsync(IEnumerable<Guid> tagIds, string userId, CancellationToken ct = default);
    Task<bool> NameExistsAsync(string userId, string name, Guid? excludeId, CancellationToken ct = default);
    void Add(Tag tag);
    /// <summary>Removes the tag and its secret mappings.</summary>
    Task RemoveAsync(Tag tag, CancellationToken ct = default);
    Task SaveChangesAsync(CancellationToken ct = default);
}

public interface ISecretService
{
    Task<ServiceResult<SecretResponse>> CreateAsync(string userId, CreateSecretRequest request);
    Task<PagedResult<SecretSummary>> ListAsync(string userId, SecretQuery query);
    Task<ServiceResult<SecretResponse>> GetAsync(string userId, Guid secretId);
    Task<ServiceResult<SecretResponse>> UpdateAsync(string userId, Guid secretId, UpdateSecretRequest request);
    Task<ServiceResult<bool>> DeleteAsync(string userId, Guid secretId);
    Task<ServiceResult<SecretResponse>> SetArchivedAsync(string userId, Guid secretId, bool archived);
    Task<ServiceResult<IReadOnlyList<SecretVersionResponse>>> GetVersionsAsync(string userId, Guid secretId);
    Task<ServiceResult<SecretResponse>> CreateVersionAsync(string userId, Guid secretId, CreateSecretVersionRequest request);
}

public interface ITagService
{
    Task<IReadOnlyList<TagDto>> ListAsync(string userId);
    Task<ServiceResult<TagDto>> CreateAsync(string userId, TagRequest request);
    Task<ServiceResult<TagDto>> RenameAsync(string userId, Guid tagId, TagRequest request);
    Task<ServiceResult<bool>> DeleteAsync(string userId, Guid tagId);
}
