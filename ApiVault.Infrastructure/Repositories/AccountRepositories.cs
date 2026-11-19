using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace ApiVault.Infrastructure.Repositories;

public class RefreshTokenRepository(AppDbContext db) : IRefreshTokenRepository
{
    public async Task AddAsync(RefreshToken token, CancellationToken ct = default)
    {
        db.RefreshTokens.Add(token);
        await db.SaveChangesAsync(ct);
    }

    public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken ct = default) =>
        db.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);

    public async Task RotateAsync(RefreshToken old, RefreshToken replacement, CancellationToken ct = default)
    {
        old.RevokedAt = DateTime.UtcNow;
        old.ReplacedByTokenId = replacement.Id;
        db.RefreshTokens.Add(replacement);
        await db.SaveChangesAsync(ct); // one transaction
    }

    public async Task RevokeAsync(RefreshToken token, CancellationToken ct = default)
    {
        token.RevokedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    public async Task RevokeAllForUserAsync(string userId, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        await db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, now), ct);
    }
}

public class SecurityEventRepository(AppDbContext db) : ISecurityEventRepository
{
    public async Task AddAsync(string userId, string eventType, ClientContext context, CancellationToken ct = default)
    {
        db.SecurityEvents.Add(new SecurityEvent
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            EventType = eventType,
            IpAddress = Truncate(context.IpAddress, 45),
            UserAgent = Truncate(context.UserAgent, 500),
            CreatedAt = DateTime.UtcNow,
        });
        await db.SaveChangesAsync(ct);
    }

    private static string? Truncate(string? v, int max) => v is null ? null : v.Length <= max ? v : v[..max];
}
