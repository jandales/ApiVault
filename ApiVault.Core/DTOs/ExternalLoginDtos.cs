namespace ApiVault.Core.DTOs;

/// <summary>An identity proven by an external provider (validated ID token).</summary>
public record ExternalIdentity(string Provider, string Subject, string Email, bool EmailVerified, string? Name);

/// <summary>
/// Either the user is signed in (existing or newly linked account), or a new account must be set up in the browser
/// first, because only the browser can create the encryption keys.
/// </summary>
public record ExternalSignInOutcome(AuthResult? SignedIn, ExternalIdentity? NeedsSetup);

/// <summary>
/// Completes a Google sign-up. <see cref="Ticket"/> is the short-lived, server-signed proof of the Google identity;
/// <see cref="Password"/> is the browser-derived authentication key, never the real password.
/// </summary>
public record GoogleRegisterRequest(string Ticket, string Password, CreateVaultRequest Vault);

public record AuthProvidersResponse(bool Google);
