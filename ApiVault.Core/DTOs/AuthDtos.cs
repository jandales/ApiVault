namespace ApiVault.Core.DTOs;

/*
 * Single-password model: the browser derives two keys from the user's password with Argon2id + HKDF.
 *   - an authentication key, sent as "Password" below (the server never sees the real password)
 *   - a key-encryption key that stays in the browser and unwraps the vault key.
 */

/// <summary>Registration creates the account and its single vault atomically.</summary>
public record RegisterRequest(string Email, string Password, CreateVaultRequest Vault);
public record LoginRequest(string Email, string Password);
public record VerifyEmailRequest(string Email, string Token);
public record ForgotPasswordRequest(string Email);

/// <summary>Returns the KDF salt and parameters the browser needs before it can derive the authentication key.</summary>
public record PreloginRequest(string Email);
public record PreloginResponse(string KdfAlgorithm, byte[] KdfSalt, string KdfParameters);

/// <summary>With a valid reset token, returns the encrypted recovery wrapper so the browser can re-key with the recovery key.</summary>
public record RecoveryMaterialRequest(string Email, string Token);
public record RecoveryMaterialResponse(Guid VaultId, KeyWrapperResponse? RecoveryWrapper);

/// <summary>New KDF salt/parameters and the same vault key wrapped under the new password-derived key.</summary>
public record VaultKeyUpdate(byte[] KdfSalt, string KdfParameters, KeyWrapperRequest PasswordWrapper);

/// <summary>
/// Exactly one of <see cref="KeyUpdate"/> (keep secrets: the browser re-wrapped the existing vault key using the recovery key)
/// or <see cref="ReplacementVault"/> (recovery key lost: the old vault and its secrets are erased and a new empty vault is created).
/// </summary>
public record ResetPasswordRequest(
    string Email,
    string Token,
    string NewPassword,
    VaultKeyUpdate? KeyUpdate = null,
    CreateVaultRequest? ReplacementVault = null);

public record UserDto(string Id, string Email, bool EmailConfirmed);

public record AuthResponse(string AccessToken, DateTime ExpiresAt, UserDto User);

/// <summary>Service-level result; the raw refresh token reaches the browser only as an HttpOnly cookie.</summary>
public record AuthResult(AuthResponse Response, string RawRefreshToken, DateTime RefreshExpiresAt);
