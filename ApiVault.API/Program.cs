using System.Text;
using System.Threading.RateLimiting;
using ApiVault.API.Middleware;
using ApiVault.BusinessLayer.Implementation;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure;
using ApiVault.Infrastructure.Data;
using ApiVault.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwt = builder.Configuration.GetSection(JwtOptions.Section).Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrWhiteSpace(jwt.Key) || jwt.Key.Length < 32)
    throw new InvalidOperationException("Jwt:Key must be configured with at least 32 characters (use user-secrets or environment variables).");

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (string.IsNullOrWhiteSpace(connectionString))
    throw new InvalidOperationException("ConnectionStrings:DefaultConnection is not configured.");

var smtp = builder.Configuration.GetSection(SmtpOptions.Section).Get<SmtpOptions>();
builder.Services.AddInfrastructure(connectionString, jwt, smtp);

// Decoy-salt secret for /auth/prelogin. Use a dedicated value if configured, otherwise derive one from the JWT key.
var preloginSecret = builder.Configuration["Auth:PreloginSecret"] is { Length: >= 32 } configured
    ? Encoding.UTF8.GetBytes(configured)
    : System.Security.Cryptography.HMACSHA256.HashData(Encoding.UTF8.GetBytes(jwt.Key), "apivault:prelogin-decoy"u8.ToArray());

builder.Services.AddSingleton(new AuthOptions
{
    RequireConfirmedEmail = builder.Configuration.GetValue<bool>("Auth:RequireConfirmedEmail"),
    FrontendUrl = builder.Configuration["Auth:FrontendUrl"] ?? "http://localhost:5173",
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

app.UseMiddleware<ExceptionHandlingMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    using var scope = app.Services.CreateScope();
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.Migrate();
}
else
{
    app.UseHsts();
    // Not in Development: the Vite dev proxy forwards to http://localhost:5149, and a redirect to the
    // HTTPS port would be cross-origin, where browsers strip the Authorization header.
    app.UseHttpsRedirection();
}

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program;
