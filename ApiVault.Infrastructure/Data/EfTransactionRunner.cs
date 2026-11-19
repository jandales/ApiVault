using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;

namespace ApiVault.Infrastructure.Data;

/// <summary>
/// Wraps work (including ASP.NET Identity calls, which share the same scoped DbContext) in one transaction.
/// Commits only when the result succeeded; any failure or exception rolls everything back.
/// </summary>
public class EfTransactionRunner(AppDbContext db) : ITransactionRunner
{
    public async Task<ServiceResult<T>> InTransactionAsync<T>(Func<Task<ServiceResult<T>>> work)
    {
        if (db.Database.CurrentTransaction is not null) return await work();

        await using var tx = await db.Database.BeginTransactionAsync();
        var result = await work();
        if (result.Succeeded) await tx.CommitAsync();
        else
        {
            await tx.RollbackAsync();
            db.ChangeTracker.Clear(); // drop entities from the rolled-back attempt
        }
        return result;
    }
}
