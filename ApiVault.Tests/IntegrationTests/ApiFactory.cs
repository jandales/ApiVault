using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

public class ApiFactory : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    public CapturingEmailSender Email { get; } = new();
    public FakeGoogleAuthClient Google { get; } = new();

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
            // Drop every registration the SQL Server AddDbContext call produced, then register SQLite.
            foreach (var d in services.Where(d => d.ServiceType == typeof(AppDbContext)
                         || d.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToList())
                services.Remove(d);
            _connection.Open();
            services.AddDbContext<AppDbContext>(o => o.UseSqlite(_connection));
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Email);
            services.RemoveAll<IGoogleAuthClient>();
            services.AddSingleton<IGoogleAuthClient>(Google);
        });
    }

    public void EnsureDatabase()
    {
        using var scope = Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing) _connection.Dispose();
    }
}
