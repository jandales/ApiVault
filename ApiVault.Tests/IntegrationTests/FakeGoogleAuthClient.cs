using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace ApiVault.Tests.IntegrationTests;

/// <summary>
/// Stands in for Google: records what the app sent to the authorize endpoint and, on code exchange, checks the
/// PKCE verifier and nonce exactly like a real ID-token validation would, returning the identity registered for the code.
/// </summary>
public class FakeGoogleAuthClient : IGoogleAuthClient
{
    public ConcurrentDictionary<string, ExternalIdentity> Codes { get; } = new();
    private readonly ConcurrentDictionary<string, (string Challenge, string Nonce)> _byState = new();
    private string? _lastState;

    public bool IsConfigured => true;
    public string RedirectUri => "http://localhost:5173/api/v1/auth/google/callback";

    public string BuildAuthorizationUrl(string state, string codeChallenge, string nonce)
    {
        _byState[state] = (codeChallenge, nonce);
        _lastState = state;
        return $"https://accounts.google.com/o/oauth2/v2/auth?state={Uri.EscapeDataString(state)}&code_challenge={codeChallenge}&code_challenge_method=S256&nonce={nonce}";
    }

    public Task<ExternalIdentity?> ExchangeCodeAsync(string code, string codeVerifier, string expectedNonce, CancellationToken ct = default)
    {
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
        var match = _byState.Values.Any(v => v.Challenge == challenge && v.Nonce == expectedNonce);
        return Task.FromResult(match && Codes.TryRemove(code, out var id) ? id : null);
    }

    public string? LastState => _lastState;
}
