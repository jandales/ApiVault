using ApiVault.Infrastructure.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace ApiVault.Tests.UnitTests;

public class DatabaseSettingsTests
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    [Fact]
    public void Railway_style_database_url_selects_postgres_and_parses_every_part()
    {
        var s = DatabaseSettings.Resolve(Config(
            ("DATABASE_URL", "postgresql://postgres:p%40ss%3Aword@postgres.railway.internal:5432/railway"),
            ("ConnectionStrings:DefaultConnection", "Server=ignored")));

        Assert.Equal(DatabaseProvider.Postgres, s.Provider);
        var cs = new NpgsqlConnectionStringBuilder(s.ConnectionString);
        Assert.Equal("postgres.railway.internal", cs.Host);
        Assert.Equal(5432, cs.Port);
        Assert.Equal("postgres", cs.Username);
        Assert.Equal("p@ss:word", cs.Password); // URL-escaped characters are decoded
        Assert.Equal("railway", cs.Database);
        Assert.Equal(SslMode.Prefer, cs.SslMode);
    }

    [Fact]
    public void Sslmode_in_the_url_is_respected_and_default_port_applies()
    {
        var cs = new NpgsqlConnectionStringBuilder(DatabaseSettings.FromUrl("postgres://u:p@db.example.com/app?sslmode=require"));
        Assert.Equal(SslMode.Require, cs.SslMode);
        Assert.Equal(5432, cs.Port);
    }

    [Fact]
    public void Without_database_url_the_configured_provider_and_connection_string_are_used()
    {
        var sql = DatabaseSettings.Resolve(Config(("ConnectionStrings:DefaultConnection", "Server=localhost;Database=x")));
        Assert.Equal(DatabaseProvider.SqlServer, sql.Provider);

        var pg = DatabaseSettings.Resolve(Config(("Database:Provider", "postgres"), ("ConnectionStrings:DefaultConnection", "Host=localhost")));
        Assert.Equal(DatabaseProvider.Postgres, pg.Provider);
        Assert.Equal("Host=localhost", pg.ConnectionString);
    }

    [Fact]
    public void Missing_configuration_and_wrong_scheme_fail_clearly()
    {
        Assert.Throws<InvalidOperationException>(() => DatabaseSettings.Resolve(Config()));
        Assert.Throws<InvalidOperationException>(() => DatabaseSettings.FromUrl("mysql://u:p@h/db"));
    }
}
