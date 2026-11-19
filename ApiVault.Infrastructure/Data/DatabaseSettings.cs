using Microsoft.Extensions.Configuration;
using Npgsql;

namespace ApiVault.Infrastructure.Data;

public enum DatabaseProvider
{
    SqlServer,
    Postgres,
}

/// <summary>
/// Which database to use and how to reach it.
/// <list type="bullet">
/// <item>If <c>DATABASE_URL</c> is set (Railway, Heroku-style <c>postgres://user:pass@host:port/db</c>), PostgreSQL is used.</item>
/// <item>Otherwise <c>Database:Provider</c> (<c>SqlServer</c> default, or <c>Postgres</c>) with <c>ConnectionStrings:DefaultConnection</c>.</item>
/// </list>
/// </summary>
public sealed record DatabaseSettings(DatabaseProvider Provider, string ConnectionString)
{
    public const string PostgresMigrationsAssembly = "ApiVault.Migrations.Postgres";

    public static DatabaseSettings Resolve(IConfiguration config)
    {
        var url = config["DATABASE_URL"];
        if (!string.IsNullOrWhiteSpace(url)) return new DatabaseSettings(DatabaseProvider.Postgres, FromUrl(url));

        var provider = Enum.TryParse<DatabaseProvider>(config["Database:Provider"], ignoreCase: true, out var p) ? p : DatabaseProvider.SqlServer;
        var connectionString = config.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException("No database configured: set DATABASE_URL or ConnectionStrings:DefaultConnection.");
        return new DatabaseSettings(provider, connectionString);
    }

    /// <summary>Converts <c>postgres://user:pass@host:port/db?sslmode=...</c> into an Npgsql connection string.</summary>
    public static string FromUrl(string url)
    {
        var uri = new Uri(url);
        if (uri.Scheme is not ("postgres" or "postgresql"))
            throw new InvalidOperationException("DATABASE_URL must start with postgres:// or postgresql://.");

        var userInfo = uri.UserInfo.Split(':', 2);
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = uri.Host,
            Port = uri.Port > 0 ? uri.Port : 5432,
            Username = Uri.UnescapeDataString(userInfo[0]),
            Password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : null,
            Database = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')),
            // Railway's private network is plain TCP; its public proxy offers TLS. Prefer works for both.
            SslMode = SslMode.Prefer,
        };

        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        if (query["sslmode"] is { } ssl && Enum.TryParse<SslMode>(ssl, ignoreCase: true, out var mode)) builder.SslMode = mode;
        return builder.ConnectionString;
    }
}
