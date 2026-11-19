using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;

namespace ApiVault.Core.Interfaces;

public interface IVaultRepository
{
    Task<bool> ExistsAsync(Guid vaultId, CancellationToken ct = default);
    Task AddAsync(Vault vault, CancellationToken ct = default);
    /// <summary>Returns the vault only if it belongs to <paramref name="userId"/>.</summary>
    Task<Vault?> GetOwnedAsync(Guid vaultId, string userId, CancellationToken ct = default);
    /// <summary>The user's single vault (tracked), or null.</summary>
    Task<Vault?> GetByUserAsync(string userId, CancellationToken ct = default);
    Task<(IReadOnlyList<Vault> Items, int Total)> ListByUserAsync(string userId, int page, int pageSize, CancellationToken ct = default);
    Task<IReadOnlyList<VaultKeyWrapper>> GetWrappersAsync(Guid vaultId, CancellationToken ct = default);
    /// <summary>Replaces the single active wrapper of this type, or adds it.</summary>
    Task<VaultKeyWrapper> UpsertWrapperAsync(Vault vault, VaultKeyWrapper wrapper, CancellationToken ct = default);
    Task UpdateAsync(Vault vault, CancellationToken ct = default);
    Task DeleteAsync(Vault vault, CancellationToken ct = default);
}

public interface IRefreshTokenRepository
{
    Task AddAsync(RefreshToken token, CancellationToken ct = default);
    Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken ct = default);
    /// <summary>Atomically revokes <paramref name="old"/> and stores <paramref name="replacement"/>.</summary>
    Task RotateAsync(RefreshToken old, RefreshToken replacement, CancellationToken ct = default);
    Task RevokeAsync(RefreshToken token, CancellationToken ct = default);
    Task RevokeAllForUserAsync(string userId, CancellationToken ct = default);
}

public interface ISecurityEventRepository
{
    Task AddAsync(string userId, string eventType, ClientContext context, CancellationToken ct = default);
}
