using System.Net.Http.Json;
using System.Text.Json.Serialization;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Google.Apis.Auth;
using Microsoft.Extensions.Logging;

namespace ApiVault.Infrastructure.Services;

public class GoogleOptions
{
    public const string Section = "Google";
    public string ClientId { get; set; } = string.Empty;
    /// <summary>Keep out of appsettings: use user-secrets or an environment variable.</summary>
    public string ClientSecret { get; set; } = string.Empty;
    /// <summary>Must exactly match an "Authorized redirect URI" in Google Cloud Console.</summary>
    public string RedirectUri { get; set; } = string.Empty;
    public bool IsConfigured => !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret) && !string.IsNullOrWhiteSpace(RedirectUri);
}

/// <summary>
/// Google sign-in via the authorization-code flow with PKCE, run entirely on the server. The browser only follows
/// redirects, so no Google script is loaded into pages that display decrypted secrets.
/// </summary>
public class GoogleAuthClient(HttpClient http, GoogleOptions options, ILogger<GoogleAuthClient> logger) : IGoogleAuthClient
{
    public const string Provider = "Google";
    private const string AuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string TokenEndpoint = "https://oauth2.googleapis.com/token";

    public bool IsConfigured => options.IsConfigured;
    public string RedirectUri => options.RedirectUri;

    public string BuildAuthorizationUrl(string state, string codeChallenge, string nonce)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"] = options.ClientId,
            ["redirect_uri"] = options.RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile",
            ["state"] = state,
            ["nonce"] = nonce,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["prompt"] = "select_account",
        };
        return AuthorizeEndpoint + "?" + string.Join("&", query.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
    }

    public async Task<ExternalIdentity?> ExchangeCodeAsync(string code, string codeVerifier, string expectedNonce, CancellationToken ct = default)
    {
        using var response = await http.PostAsync(TokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret,
            ["redirect_uri"] = options.RedirectUri,
            ["grant_type"] = "authorization_code",
            ["code_verifier"] = codeVerifier,
        }), ct);
        if (!response.IsSuccessStatusCode)
        {
            logger.LogWarning("Google token exchange failed with {Status}", (int)response.StatusCode);
            return null;
        }

        var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(ct);
        if (string.IsNullOrEmpty(tokens?.IdToken)) return null;

        try
        {
            // Verifies Google's signature, issuer, audience (our client id) and expiry.
            var payload = await GoogleJsonWebSignature.ValidateAsync(tokens.IdToken,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [options.ClientId] });
            if (payload.Nonce != expectedNonce) return null;
            return new ExternalIdentity(Provider, payload.Subject, payload.Email ?? string.Empty, payload.EmailVerified, payload.Name);
        }
        catch (InvalidJwtException ex)
        {
            logger.LogWarning("Rejected Google ID token: {Error}", ex.Message);
            return null;
        }
    }

    private sealed record TokenResponse([property: JsonPropertyName("id_token")] string? IdToken);
}
