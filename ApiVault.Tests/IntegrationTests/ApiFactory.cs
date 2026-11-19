using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

namespace ApiVault.Tests.IntegrationTests;

public class CapturingEmailSender : IEmailSender
{
    public List<(string To, string Subject, string Body)> Sent { get; } = [];
    public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        lock (Sent) Sent.Add((toEmail, subject, body));
        return Task.CompletedTask;
    }
}

/// <summary>
/// Test host. Uses in-memory SQLite by default. Set APIVAULT_TEST_POSTGRES to a PostgreSQL connection string
/// (any database; it is only used to reach the server) to run the same tests against real PostgreSQL: each factory
/// creates its own throwaway database, applies the real PostgreSQL migrations, and drops it afterwards.
/// </summary>
public class ApiFactory : WebApplicationFactory<Program>
{
    private static readonly string? PostgresServer = Environment.GetEnvironmentVariable("APIVAULT_TEST_POSTGRES");
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly string? _postgres = PostgresServer is null
        ? null
        : new NpgsqlConnectionStringBuilder(PostgresServer) { Database = $"apivault_test_{Guid.NewGuid():N}" }.ConnectionString;
    private readonly object _dbLock = new();
    private bool _databaseReady;

    public CapturingEmailSender Email { get; } = new();
    public FakeGoogleAuthClient Google { get; } = new();
    public bool UsesPostgres => _postgres is not null;

    static ApiFactory()
    {
        Environment.SetEnvironmentVariable("Jwt__Key", "integration-test-signing-key-0123456789abcdef");
        Environment.SetEnvironmentVariable("ConnectionStrings__DefaultConnection", "Server=unused;Database=unused");
        Environment.SetEnvironmentVariable("Auth__RequireConfirmedEmail", "false");
        Environment.SetEnvironmentVariable("RateLimiting__AuthPermitLimit", "10000");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureServices(services =>
        {
            // Replace only the database registrations from the app's AddDbContext call (keep e.g. the health check).
            foreach (var d in services.Where(d => d.ServiceType == typeof(AppDbContext)
                         || (d.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext)) && d.ServiceType.Name.Contains("DbContextOptions"))).ToList())
                services.Remove(d);
            if (_postgres is not null)
            {
                services.AddDbContext<AppDbContext>(o =>
                    o.UseNpgsql(_postgres, x => x.MigrationsAssembly(DatabaseSettings.PostgresMigrationsAssembly)));
            }
            else
            {
                _connection.Open();
                services.AddDbContext<AppDbContext>(o => o.UseSqlite(_connection));
            }
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Email);
            services.RemoveAll<IGoogleAuthClient>();
            services.AddSingleton<IGoogleAuthClient>(Google);
        });
    }

    public void EnsureDatabase()
    {
        lock (_dbLock)
        {
            if (_databaseReady) return;
            using var scope = Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>().Database;
            if (_postgres is not null) db.Migrate(); // the real PostgreSQL migrations, not EnsureCreated
            else db.EnsureCreated();
            _databaseReady = true;
        }
    }

    /// <summary>xUnit disposes fixtures asynchronously; drop the throwaway database while the host is still alive.</summary>
    public override async ValueTask DisposeAsync()
    {
        await DropPostgresDatabaseAsync();
        await base.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    private async Task DropPostgresDatabaseAsync()
    {
        if (_postgres is null || !_databaseReady) return;
        _databaseReady = false;
        // A fresh context, independent of the host's service provider.
        var options = new DbContextOptionsBuilder<AppDbContext>().UseNpgsql(_postgres).Options;
        await using var db = new AppDbContext(options);
        await db.Database.EnsureDeletedAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) DropPostgresDatabaseAsync().GetAwaiter().GetResult();
        base.Dispose(disposing);
        if (disposing) _connection.Dispose();
    }
}
