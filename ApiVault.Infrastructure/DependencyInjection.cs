using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Data;
using ApiVault.Infrastructure.Identity;
using ApiVault.Infrastructure.Repositories;
using ApiVault.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiVault.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, string connectionString, JwtOptions jwt, SmtpOptions? smtp = null)
    {
        services.AddDbContext<AppDbContext>(o => o.UseSqlServer(connectionString));

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
        if (smtp is { IsConfigured: true })
        {
            services.AddSingleton(smtp);
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
        }
        else
        {
            services.AddSingleton<IEmailSender, LoggingEmailSender>(); // development fallback: link appears in the API log
        }
        return services;
    }
}
