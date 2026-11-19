using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ApiVault.Infrastructure.Services;

public class JwtOptions
{
    public const string Section = "Jwt";
    public string Issuer { get; set; } = "ApiVault";
    public string Audience { get; set; } = "ApiVault.Web";
    /// <summary>Symmetric signing key, at least 32 characters. Supply via user-secrets or environment variables.</summary>
    public string Key { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 10;
    public int RefreshTokenDays { get; set; } = 14;
}

public class TokenService(JwtOptions options) : ITokenService
{
    public TimeSpan RefreshTokenLifetime => TimeSpan.FromDays(options.RefreshTokenDays);

    public (string Token, DateTime ExpiresAt) CreateAccessToken(UserDto user)
    {
        var expires = DateTime.UtcNow.AddMinutes(options.AccessTokenMinutes);
        var creds = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Key)), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            options.Issuer,
            options.Audience,
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            ],
            expires: expires,
            signingCredentials: creds);
        return (new JwtSecurityTokenHandler().WriteToken(token), expires);
    }

    public string GenerateRefreshToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(64));

    public string HashToken(string rawToken) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
}

/// <summary>
/// Development-only sender: writes the message to the log instead of sending email.
/// Replace with a real provider before deployment.
/// </summary>
public class LoggingEmailSender(Microsoft.Extensions.Logging.ILogger<LoggingEmailSender> logger) : IEmailTransport
{
    public Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default)
    {
        logger.LogDebug("DEV EMAIL to {To}: {Subject}\n{Body}", toEmail, subject, body);
        return Task.CompletedTask;
    }
}
