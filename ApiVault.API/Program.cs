using System.Text;
using System.Threading.RateLimiting;
using ApiVault.API.Middleware;
using ApiVault.BusinessLayer.Implementation;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure;
using ApiVault.Infrastructure.Data;
using ApiVault.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwt = builder.Configuration.GetSection(JwtOptions.Section).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrWhiteSpace(jwt.Key) || jwt.Key.Length < 32)
    throw new InvalidOperationException("Jwt:Key must be configured with at least 32 characters (use user-secrets or environment variables).");

// SQL Server locally; PostgreSQL when DATABASE_URL is set (Railway) or Database:Provider=Postgres.
var database = DatabaseSettings.Resolve(builder.Configuration);

// Railway (and most PaaS) tell the app which port to listen on. Bind all interfaces, IPv4 and IPv6
// (Railway's private network is IPv6).
if (Environment.GetEnvironmentVariable("PORT") is { Length: > 0 } port)
    builder.WebHost.UseUrls($"http://+:{port}");

// Behind Railway's edge proxy, TLS ends at the proxy: trust its X-Forwarded-* headers so the real client IP is
// used for rate limiting. Only enabled when actually behind such a proxy, otherwise clients could spoof their IP.
var behindProxy = builder.Configuration.GetValue("Hosting:BehindProxy",
    !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("RAILWAY_ENVIRONMENT_NAME")));
if (behindProxy)
{
    builder.Services.Configure<ForwardedHeadersOptions>(o =>
    {
        o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        o.KnownIPNetworks.Clear();
        o.KnownProxies.Clear();
        // Hops to walk back through X-Forwarded-For. Default 2 = Railway edge → frontend Caddy → API, which is
        // the intended topology (the API has no public domain). Use 1 if clients reach the API through the edge only.
        o.ForwardLimit = builder.Configuration.GetValue("Hosting:ForwardLimit", 2);
    });
}

var frontendUrl = (builder.Configuration["Auth:FrontendUrl"] is { Length: > 0 } fe ? fe : "http://localhost:5173").TrimEnd('/');

var smtp = builder.Configuration.GetSection(SmtpOptions.Section).Get<SmtpOptions>();

// Google sign-in is enabled when ClientId and ClientSecret are set. The callback goes through the frontend origin
// (the Vite dev proxy forwards /api), so cookies stay first-party. Register this exact URI in Google Cloud Console.
var google = builder.Configuration.GetSection(GoogleOptions.Section).Get<GoogleOptions>() ?? new GoogleOptions();
if (string.IsNullOrWhiteSpace(google.RedirectUri)) google.RedirectUri = $"{frontendUrl}/api/v1/auth/google/callback";

builder.Services.AddInfrastructure(database, jwt, smtp, google);
builder.Services.AddHealthChecks().AddDbContextCheck<AppDbContext>("database");

// Decoy-salt secret for /auth/prelogin. Use a dedicated value if configured, otherwise derive one from the JWT key.
var preloginSecret = builder.Configuration["Auth:PreloginSecret"] is { Length: >= 32 } configured
    ? Encoding.UTF8.GetBytes(configured)
    : System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(jwt.Key), "apivault:prelogin-decoy"u8.ToArray());

builder.Services.AddSingleton(new AuthOptions
{
    RequireConfirmedEmail = builder.Configuration.GetValue<bool>("Auth:RequireConfirmedEmail"),
    FrontendUrl = frontendUrl,
    PreloginSecret = preloginSecret,
});
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IVaultService, VaultService>();
builder.Services.AddScoped<ISecretService, SecretService>();
builder.Services.AddScoped<ITagService, TagService>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        };
    });
builder.Services.AddAuthorization();

var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
{
    if (origins.Length > 0)
        p.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials();
}));

var permit = builder.Configuration.GetValue("RateLimiting:AuthPermitLimit", 10);
var window = builder.Configuration.GetValue("RateLimiting:AuthWindowSeconds", 60);
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = permit, Window = TimeSpan.FromSeconds(window), QueueLimit = 0 }));
});

var app = builder.Build();

// Startup diagnostics: which optional integrations are on, and (in Development) which config sources loaded.
// Never logs values, only whether settings are present.
{
    var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("ApiVault.Startup");
    var missing = new[] { ("ClientId", google.ClientId), ("ClientSecret", google.ClientSecret), ("RedirectUri", google.RedirectUri) }
        .Where(x => string.IsNullOrWhiteSpace(x.Item2)).Select(x => x.Item1).ToArray();
    if (missing.Length == 0) startupLog.LogInformation("Google sign-in: enabled (redirect URI {RedirectUri})", google.RedirectUri);
    else startupLog.LogWarning("Google sign-in: disabled, missing Google:{Missing}", string.Join(", Google:", missing));
    startupLog.LogInformation("Email: {Mode}", smtp is { IsConfigured: true } ? $"SMTP via {smtp.Host}" : "development log only (no SMTP configured)");
    startupLog.LogInformation("Database: {Provider}; behind proxy: {BehindProxy}", database.Provider, behindProxy);
    if (app.Environment.IsDevelopment())
    {
        var sources = ((IConfigurationRoot)app.Configuration).Providers.Select(p => p.ToString());
        startupLog.LogInformation("Environment {Env}; config sources: {Sources}", app.Environment.EnvironmentName, string.Join(" | ", sources));
    }
}

if (behindProxy) app.UseForwardedHeaders();
app.UseMiddleware<ExceptionHandlingMiddleware>();

// Apply migrations automatically in Development, and in production when Database:MigrateOnStartup=true
// (set in the Dockerfile for single-instance deployments like Railway).
if (app.Environment.IsDevelopment() || app.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
{
    using var scope = app.Services.CreateScope();
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.Migrate();
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else if (!behindProxy)
{
    // Behind Railway the edge proxy already enforces HTTPS (and its health checks use plain HTTP), so only
    // redirect when the app terminates TLS itself. Never in Development: the Vite proxy forwards to HTTP and a
    // cross-origin redirect would strip the Authorization header.
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Liveness + database reachability, for the platform's health check.
app.MapHealthChecks("/health");

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program;
