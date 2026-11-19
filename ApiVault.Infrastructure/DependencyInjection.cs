using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using ApiVault.Infrastructure.Identity;
using ApiVault.Infrastructure.Repositories;
using ApiVault.Infrastructure.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiVault.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, DatabaseSettings database, JwtOptions jwt, SmtpOptions? smtp = null, GoogleOptions? google = null)
    {
        services.AddDbContext<AppDbContext>(o =>
        {
            if (database.Provider == DatabaseProvider.Postgres)
                o.UseNpgsql(database.ConnectionString, x => x.MigrationsAssembly(DatabaseSettings.PostgresMigrationsAssembly));
            else
                o.UseSqlServer(database.ConnectionString);
        });

        // Keys protect Identity tokens and the Google sign-in cookies; stored in the database so redeploys
        // and multiple instances share them (containers have no persistent disk).
        services.AddDataProtection()
            .SetApplicationName("ApiVault")
            .PersistKeysToDbContext<AppDbContext>();

        services.AddIdentityCore<ApplicationUser>(o =>
            {
                // The "password" the server receives is a 256-bit key the browser derives with Argon2id + HKDF
                // (base64, 44 chars). Real password strength is enforced in the browser; the server only rejects
                // values too short to be such a key, so a raw password sent by mistake is refused.
                o.Password.RequiredLength = 32;
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.User.RequireUniqueEmail = true;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        services.AddSingleton(jwt);
        services.AddSingleton<ITokenService, TokenService>();
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddScoped<IVaultRepository, VaultRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<ISecurityEventRepository, SecurityEventRepository>();
        services.AddScoped<ITransactionRunner, EfTransactionRunner>();
        services.AddScoped<ISecretRepository, SecretRepository>();
        services.AddScoped<ITagRepository, TagRepository>();
        // Email: requests only enqueue; a background worker delivers (see EmailQueue.cs for why).
        if (smtp is { IsConfigured: true })
        {
            services.AddSingleton(smtp);
            services.AddSingleton<IEmailTransport, SmtpEmailSender>();
        }
        else
        {
            services.AddSingleton<IEmailTransport, LoggingEmailSender>(); // development fallback: link appears in the API log
        }
        services.AddSingleton(google ?? new GoogleOptions());
        services.AddHttpClient<IGoogleAuthClient, GoogleAuthClient>();
        services.AddSingleton<EmailQueue>();
        services.AddSingleton<IEmailSender, QueuedEmailSender>();
        services.AddHostedService<EmailDeliveryService>();
        return services;
    }
}
