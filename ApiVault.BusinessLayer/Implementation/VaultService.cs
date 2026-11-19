using ApiVault.BusinessLayer.Validators;
using ApiVault.Core.Constants;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;

namespace ApiVault.BusinessLayer.Implementation;

/// <summary>Read and metadata operations on the account's single vault. Creation happens at registration.</summary>
public class VaultService(IVaultRepository vaults, ISecurityEventRepository events) : IVaultService
{
    public async Task<PagedResult<VaultResponse>> ListAsync(string userId, int page, int pageSize)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);
        var (items, total) = await vaults.ListByUserAsync(userId, page, pageSize);
        return new PagedResult<VaultResponse>(items.Select(VaultFactory.ToResponse).ToList(), page, pageSize, total);
    }

    public async Task<ServiceResult<VaultResponse>> GetAsync(string userId, Guid vaultId)
    {
        var vault = await vaults.GetOwnedAsync(vaultId, userId);
        return vault is null ? NotFound<VaultResponse>() : ServiceResult<VaultResponse>.Ok(VaultFactory.ToResponse(vault));
    }

    public async Task<ServiceResult<VaultResponse>> UpdateAsync(string userId, Guid vaultId, UpdateVaultRequest request)
    {
        var errors = VaultValidator.ValidateUpdate(request);
        if (errors.Count > 0) return ServiceResult<VaultResponse>.Fail(ErrorKind.Validation, "Invalid vault request.", errors);

        var vault = await vaults.GetOwnedAsync(vaultId, userId);
        if (vault is null) return NotFound<VaultResponse>();

        vault.Name = request.Name.Trim();
        vault.Description = request.Description?.Trim();
        vault.ModifiedAt = DateTime.UtcNow;
        await vaults.UpdateAsync(vault);
        return ServiceResult<VaultResponse>.Ok(VaultFactory.ToResponse(vault));
    }

    public async Task<ServiceResult<IReadOnlyList<KeyWrapperResponse>>> GetWrappersAsync(string userId, Guid vaultId)
    {
        var vault = await vaults.GetOwnedAsync(vaultId, userId);
        if (vault is null) return NotFound<IReadOnlyList<KeyWrapperResponse>>();
        var wrappers = await vaults.GetWrappersAsync(vaultId);
        return ServiceResult<IReadOnlyList<KeyWrapperResponse>>.Ok(wrappers.Select(VaultFactory.ToResponse).ToList());
    }

    public async Task<ServiceResult<KeyWrapperResponse>> UpsertWrapperAsync(string userId, Guid vaultId, KeyWrapperRequest request, ClientContext ctx)
    {
        var errors = VaultValidator.ValidateWrapper(request);
        if (errors.Count > 0) return ServiceResult<KeyWrapperResponse>.Fail(ErrorKind.Validation, "Invalid key wrapper.", errors);

        var vault = await vaults.GetOwnedAsync(vaultId, userId);
        if (vault is null) return NotFound<KeyWrapperResponse>();

        var saved = await vaults.UpsertWrapperAsync(vault, VaultFactory.Wrapper(vaultId, request, DateTime.UtcNow));
        await events.AddAsync(userId, SecurityEventTypes.KeyWrapperChanged, ctx);
        return ServiceResult<KeyWrapperResponse>.Ok(VaultFactory.ToResponse(saved));
    }

    // Unknown and not-owned vaults are indistinguishable to the caller (no resource enumeration).
    private static ServiceResult<T> NotFound<T>() => ServiceResult<T>.Fail(ErrorKind.NotFound, "Vault not found.");
}
