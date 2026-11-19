using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace ApiVault.Infrastructure.Repositories;

public class SecretRepository(AppDbContext db) : ISecretRepository
{
    public Task<bool> ExistsAsync(Guid secretId, CancellationToken ct = default) =>
        db.Secrets.AnyAsync(s => s.Id == secretId, ct);

    public Task<Secret?> GetOwnedAsync(Guid secretId, string userId, CancellationToken ct = default) =>
        db.Secrets
            .Include(s => s.TagMappings).ThenInclude(m => m.Tag)
            .FirstOrDefaultAsync(s => s.Id == secretId && s.Vault!.UserId == userId, ct);

    public async Task<(IReadOnlyList<Secret> Items, int Total)> QueryAsync(string userId, SecretQuery q, CancellationToken ct = default)
    {
        var query = db.Secrets.AsNoTracking()
            .Where(s => s.Vault!.UserId == userId && s.IsArchived == q.Archived);

        if (q.VaultId is { } vaultId) query = query.Where(s => s.VaultId == vaultId);
        if (!string.IsNullOrWhiteSpace(q.SecretType)) query = query.Where(s => s.SecretType == q.SecretType);
        if (q.TagId is { } tagId) query = query.Where(s => s.TagMappings.Any(m => m.TagId == tagId));
        if (q.ExpiringWithinDays is { } days)
        {
            var cutoff = DateTime.UtcNow.AddDays(days);
            query = query.Where(s => s.ExpiresAt != null && s.ExpiresAt <= cutoff);
        }
        if (!string.IsNullOrWhiteSpace(q.Search))
        {
            // Lower-case both sides so search ignores case on every database
            // (SQL Server's default collation does; PostgreSQL's LIKE does not).
            var term = q.Search.Trim().ToLowerInvariant();
            query = query.Where(s => s.Name.ToLower().Contains(term)
                || (s.Provider != null && s.Provider.ToLower().Contains(term))
                || (s.Description != null && s.Description.ToLower().Contains(term)));
        }

        var total = await query.CountAsync(ct);
        var items = await query
            .Include(s => s.TagMappings).ThenInclude(m => m.Tag)
            .OrderByDescending(s => s.CreatedAt)
            .Skip((q.Page - 1) * q.PageSize).Take(q.PageSize)
            .ToListAsync(ct);
        return (items, total);
    }

    public async Task<IReadOnlyList<SecretVersion>> GetVersionsAsync(Guid secretId, CancellationToken ct = default) =>
        await db.SecretVersions.AsNoTracking().Where(v => v.SecretId == secretId).OrderByDescending(v => v.CreatedAt).ToListAsync(ct);

    public void Add(Secret secret) => db.Secrets.Add(secret);

    public void AddVersion(SecretVersion version) => db.SecretVersions.Add(version);

    public void Remove(Secret secret) => db.Secrets.Remove(secret);

    public Task SaveChangesAsync(CancellationToken ct = default) => db.SaveChangesAsync(ct);
}

public class TagRepository(AppDbContext db) : ITagRepository
{
    public async Task<IReadOnlyList<Tag>> ListAsync(string userId, CancellationToken ct = default) =>
        await db.Tags.AsNoTracking().Where(t => t.UserId == userId).OrderBy(t => t.Name).ToListAsync(ct);

    public Task<Tag?> GetOwnedAsync(Guid tagId, string userId, CancellationToken ct = default) =>
        db.Tags.FirstOrDefaultAsync(t => t.Id == tagId && t.UserId == userId, ct);

    public async Task<IReadOnlyList<Tag>> GetOwnedManyAsync(IEnumerable<Guid> tagIds, string userId, CancellationToken ct = default)
    {
        var ids = tagIds.ToList();
        return await db.Tags.Where(t => t.UserId == userId && ids.Contains(t.Id)).ToListAsync(ct);
    }

    public Task<bool> NameExistsAsync(string userId, string name, Guid? excludeId, CancellationToken ct = default) =>
        db.Tags.AnyAsync(t => t.UserId == userId && t.Name == name && (excludeId == null || t.Id != excludeId), ct);

    public void Add(Tag tag) => db.Tags.Add(tag);

    public async Task RemoveAsync(Tag tag, CancellationToken ct = default)
    {
        // Mappings use NoAction on the tag side (avoids SQL Server multiple cascade paths), so remove them first.
        db.SecretTagMappings.RemoveRange(await db.SecretTagMappings.Where(m => m.TagId == tag.Id).ToListAsync(ct));
        db.Tags.Remove(tag);
        await db.SaveChangesAsync(ct);
    }

    public Task SaveChangesAsync(CancellationToken ct = default) => db.SaveChangesAsync(ct);
}
