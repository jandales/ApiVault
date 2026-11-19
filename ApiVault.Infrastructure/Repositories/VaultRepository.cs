using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace ApiVault.Infrastructure.Repositories;

public class VaultRepository(AppDbContext db) : IVaultRepository
{
    public Task<bool> ExistsAsync(Guid vaultId, CancellationToken ct = default) =>
        db.Vaults.AnyAsync(v => v.Id == vaultId, ct);

    public async Task AddAsync(Vault vault, CancellationToken ct = default)
    {
        db.Vaults.Add(vault);
        await db.SaveChangesAsync(ct); // vault + wrappers in a single transaction
    }

    public Task<Vault?> GetOwnedAsync(Guid vaultId, string userId, CancellationToken ct = default) =>
        db.Vaults.FirstOrDefaultAsync(v => v.Id == vaultId && v.UserId == userId, ct);

    public Task<Vault?> GetByUserAsync(string userId, CancellationToken ct = default) =>
        db.Vaults.FirstOrDefaultAsync(v => v.UserId == userId, ct);

    public async Task<(IReadOnlyList<Vault> Items, int Total)> ListByUserAsync(string userId, int page, int pageSize, CancellationToken ct = default)
    {
        var query = db.Vaults.AsNoTracking().Where(v => v.UserId == userId);
        var total = await query.CountAsync(ct);
        var items = await query.OrderBy(v => v.CreatedAt).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return (items, total);
    }

    public async Task<IReadOnlyList<VaultKeyWrapper>> GetWrappersAsync(Guid vaultId, CancellationToken ct = default) =>
        await db.VaultKeyWrappers.AsNoTracking().Where(w => w.VaultId == vaultId).OrderBy(w => w.WrapperType).ToListAsync(ct);

    public async Task<VaultKeyWrapper> UpsertWrapperAsync(Vault vault, VaultKeyWrapper wrapper, CancellationToken ct = default)
    {
        var existing = await db.VaultKeyWrappers.FirstOrDefaultAsync(
            w => w.VaultId == vault.Id && w.WrapperType == wrapper.WrapperType, ct);
        if (existing is null)
        {
            db.VaultKeyWrappers.Add(wrapper);
            existing = wrapper;
        }
        else
        {
            existing.EncryptedVaultKey = wrapper.EncryptedVaultKey;
            existing.Nonce = wrapper.Nonce;
            existing.AuthTag = wrapper.AuthTag;
            existing.KeyVersion = wrapper.KeyVersion;
            existing.CreatedAt = wrapper.CreatedAt;
        }
        vault.ModifiedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return existing;
    }

    public Task UpdateAsync(Vault vault, CancellationToken ct = default) => db.SaveChangesAsync(ct);

    public async Task DeleteAsync(Vault vault, CancellationToken ct = default)
    {
        db.Vaults.Remove(vault); // cascades to wrappers, secrets, versions, tag mappings
        await db.SaveChangesAsync(ct);
    }
}
