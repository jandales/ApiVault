using ApiVault.Core.DTOs;

namespace ApiVault.Core.Interfaces;

/// <summary>Wraps ASP.NET Core Identity so the business layer stays framework-agnostic.</summary>
public interface IIdentityService
{
    Task<ServiceResult<UserDto>> RegisterAsync(string email, string password);
    /// <summary>Unauthorized for wrong credentials; Forbidden when locked out.</summary>
    Task<ServiceResult<UserDto>> ValidateCredentialsAsync(string email, string password);
    Task<UserDto?> GetUserAsync(string userId);
    Task<string?> FindUserIdByEmailAsync(string email);
    Task<UserDto?> FindByExternalLoginAsync(string provider, string providerKey);
    /// <summary>Links an external login to an existing account; optionally marks the email confirmed (the provider verified it).</summary>
    Task<ServiceResult<UserDto>> LinkExternalLoginAsync(string userId, string provider, string providerKey, bool confirmEmail);
    /// <summary>Creates an account with a derived auth key and a linked external login; the email is already verified.</summary>
    Task<ServiceResult<UserDto>> RegisterExternalAsync(string email, string password, string provider, string providerKey);
    /// <summary>Checks a password-reset token without consuming it. Returns the user id, or null if invalid.</summary>
    Task<string?> VerifyPasswordResetTokenAsync(string email, string token);
    Task<string?> GenerateEmailConfirmationTokenAsync(string email);
    Task<ServiceResult<UserDto>> ConfirmEmailAsync(string email, string token);
    Task<string?> GeneratePasswordResetTokenAsync(string email);
    Task<ServiceResult<UserDto>> ResetPasswordAsync(string email, string token, string newPassword);
}

public interface ITokenService
{
    (string Token, DateTime ExpiresAt) CreateAccessToken(UserDto user);
    string GenerateRefreshToken();
    string HashToken(string rawToken);
    TimeSpan RefreshTokenLifetime { get; }
}

public interface IEmailSender
{
    Task SendAsync(string toEmail, string subject, string body, CancellationToken ct = default);
}

/// <summary>Runs work in one database transaction; commits only if the result succeeded.</summary>
public interface ITransactionRunner
{
    Task<ServiceResult<T>> InTransactionAsync<T>(Func<Task<ServiceResult<T>>> work);
}

public interface IAuthService
{
    Task<PreloginResponse> PreloginAsync(PreloginRequest request);
    Task<ServiceResult<RecoveryMaterialResponse>> GetRecoveryMaterialAsync(RecoveryMaterialRequest request);
    Task<ServiceResult<UserDto>> RegisterAsync(RegisterRequest request, ClientContext ctx);
    Task<ServiceResult<AuthResult>> LoginAsync(LoginRequest request, ClientContext ctx);
    Task<ServiceResult<AuthResult>> RefreshAsync(string? rawRefreshToken, ClientContext ctx);
    Task LogoutAsync(string? rawRefreshToken, ClientContext ctx);
    Task<ServiceResult<UserDto>> VerifyEmailAsync(VerifyEmailRequest request, ClientContext ctx);
    /// <summary>Sends a new verification link to the signed-in user (no-op if already verified).</summary>
    Task<ServiceResult<bool>> ResendVerificationAsync(string userId);
    Task ForgotPasswordAsync(ForgotPasswordRequest request, ClientContext ctx);
    Task<ServiceResult<UserDto>> ResetPasswordAsync(ResetPasswordRequest request, ClientContext ctx);
    Task<UserDto?> GetCurrentUserAsync(string userId);
    Task<ServiceResult<ExternalSignInOutcome>> ExternalSignInAsync(ExternalIdentity identity, ClientContext ctx);
    Task<ServiceResult<AuthResult>> ExternalRegisterAsync(ExternalIdentity identity, string password, CreateVaultRequest vault, ClientContext ctx);
}

/// <summary>Server-side Google OAuth (authorization code + PKCE). No Google JavaScript runs in the app.</summary>
public interface IGoogleAuthClient
{
    bool IsConfigured { get; }
    string RedirectUri { get; }
    string BuildAuthorizationUrl(string state, string codeChallenge, string nonce);
    /// <summary>Exchanges the code and validates the ID token (signature, audience, expiry, nonce). Null if anything is invalid.</summary>
    Task<ExternalIdentity?> ExchangeCodeAsync(string code, string codeVerifier, string expectedNonce, CancellationToken ct = default);
}

/// <summary>Each account has exactly one vault, created at registration; it cannot be created or deleted separately.</summary>
public interface IVaultService
{
    Task<PagedResult<VaultResponse>> ListAsync(string userId, int page, int pageSize);
    Task<ServiceResult<VaultResponse>> GetAsync(string userId, Guid vaultId);
    Task<ServiceResult<VaultResponse>> UpdateAsync(string userId, Guid vaultId, UpdateVaultRequest request);
    Task<ServiceResult<IReadOnlyList<KeyWrapperResponse>>> GetWrappersAsync(string userId, Guid vaultId);
    Task<ServiceResult<KeyWrapperResponse>> UpsertWrapperAsync(string userId, Guid vaultId, KeyWrapperRequest request, ClientContext ctx);
}
