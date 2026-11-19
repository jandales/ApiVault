using ApiVault.Core.DTOs;

namespace ApiVault.API.Extensions;

/// <summary>The HttpOnly refresh-token cookie, shared by password and Google sign-in.</summary>
public static class RefreshCookie
{
    public const string Name = "av_refresh";
    public const string Path = "/api/v1/auth";

    public static string? Read(HttpRequest request) => request.Cookies[Name];

    public static void Set(HttpResponse response, AuthResult result) =>
        response.Cookies.Append(Name, result.RawRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = Path,
            Expires = result.RefreshExpiresAt,
            IsEssential = true,
        });

    public static void Clear(HttpResponse response) =>
        response.Cookies.Delete(Name, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = Path });
}
