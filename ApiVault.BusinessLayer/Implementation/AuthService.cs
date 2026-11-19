using System.Security.Cryptography;
using System.Text;
using ApiVault.BusinessLayer.Validators;
using ApiVault.Core.Constants;
using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;
using ApiVault.Core.Interfaces;

namespace ApiVault.BusinessLayer.Implementation;

public class AuthOptions
{
    public bool RequireConfirmedEmail { get; set; }
    public string FrontendUrl { get; set; } = "http://localhost:5173";
    /// <summary>Server secret used to derive stable decoy salts for unknown emails in prelogin.</summary>
    public byte[] PreloginSecret { get; set; } = [];
}

public class AuthService(
    IIdentityService identity,
    ITokenService tokens,
    IRefreshTokenRepository refreshTokens,
    ISecurityEventRepository events,
    IVaultRepository vaults,
    ITransactionRunner transactions,
    IEmailSender email,
    AuthOptions options) : IAuthService
{
    public const string DefaultKdfParameters = "{\"v\":1,\"m\":65536,\"t\":3,\"p\":1}";

    /// <summary>
    /// Returns the account's KDF salt. Unknown emails get a stable decoy salt derived from a server secret,
    /// so the response does not reveal whether an account exists.
    /// </summary>
    public async Task<PreloginResponse> PreloginAsync(PreloginRequest request)
    {
        var userId = string.IsNullOrWhiteSpace(request.Email) ? null : await identity.FindUserIdByEmailAsync(request.Email);
        var vault = userId is null ? null : await vaults.GetByUserAsync(userId);
        if (vault is not null) return new PreloginResponse(vault.KdfAlgorithm, vault.KdfSalt, vault.KdfParameters);

        var normalized = Encoding.UTF8.GetBytes((request.Email ?? string.Empty).Trim().ToUpperInvariant());
        var decoy = HMACSHA256.HashData(options.PreloginSecret, normalized)[..16];
        return new PreloginResponse(CryptoConstants.KdfAlgorithm, decoy, DefaultKdfParameters);
    }

    public async Task<ServiceResult<UserDto>> RegisterAsync(RegisterRequest request, ClientContext ctx)
    {
        if (request.Vault is null)
            return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", ["Encrypted vault key material is required."]);
        var errors = VaultValidator.ValidateCreate(request.Vault);
        if (errors.Count > 0) return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", errors);
        if (await vaults.ExistsAsync(request.Vault.Id))
            return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", ["Unable to register with these details."]);

        // Account and vault are created together or not at all.
        var result = await transactions.InTransactionAsync(async () =>
        {
            var created = await identity.RegisterAsync(request.Email, request.Password);
            if (!created.Succeeded) return created;
            await vaults.AddAsync(VaultFactory.Build(created.Value!.Id, request.Vault, DateTime.UtcNow));
            return created;
        });
        if (!result.Succeeded) return result;

        await events.AddAsync(result.Value!.Id, SecurityEventTypes.Registered, ctx);
        await events.AddAsync(result.Value.Id, SecurityEventTypes.VaultCreated, ctx);
        await SendVerificationEmailAsync(result.Value.Email);
        return result;
    }

    public async Task<ServiceResult<AuthResult>> LoginAsync(LoginRequest request, ClientContext ctx)
    {
        var result = await identity.ValidateCredentialsAsync(request.Email, request.Password);
        if (!result.Succeeded)
        {
            // Generic message: do not reveal whether the account exists.
            return ServiceResult<AuthResult>.Fail(result.Error == ErrorKind.Forbidden ? ErrorKind.Forbidden : ErrorKind.Unauthorized,
                result.Error == ErrorKind.Forbidden ? "Account temporarily locked." : "Invalid email or password.");
        }

        var user = result.Value!;
        if (options.RequireConfirmedEmail && !user.EmailConfirmed)
            return ServiceResult<AuthResult>.Fail(ErrorKind.Forbidden, "Email address is not verified.");

        await events.AddAsync(user.Id, SecurityEventTypes.LoginSucceeded, ctx);
        return ServiceResult<AuthResult>.Ok(await IssueAsync(user, null));
    }

    public async Task<ServiceResult<AuthResult>> RefreshAsync(string? rawRefreshToken, ClientContext ctx)
    {
        var invalid = ServiceResult<AuthResult>.Fail(ErrorKind.Unauthorized, "Invalid refresh token.");
        if (string.IsNullOrWhiteSpace(rawRefreshToken)) return invalid;

        var stored = await refreshTokens.FindByHashAsync(tokens.HashToken(rawRefreshToken));
        if (stored is null) return invalid;

        if (stored.RevokedAt is not null)
        {
            // A rotated/revoked token was presented again: assume theft and revoke every session of this user.
            await refreshTokens.RevokeAllForUserAsync(stored.UserId);
            await events.AddAsync(stored.UserId, SecurityEventTypes.RefreshTokenReuseDetected, ctx);
            return invalid;
        }
        if (stored.ExpiresAt <= DateTime.UtcNow) return invalid;

        var user = await identity.GetUserAsync(stored.UserId);
        if (user is null) return invalid;

        return ServiceResult<AuthResult>.Ok(await IssueAsync(user, stored));
    }

    public async Task LogoutAsync(string? rawRefreshToken, ClientContext ctx)
    {
        if (string.IsNullOrWhiteSpace(rawRefreshToken)) return;
        var stored = await refreshTokens.FindByHashAsync(tokens.HashToken(rawRefreshToken));
        if (stored is null) return;
        if (stored.RevokedAt is null) await refreshTokens.RevokeAsync(stored);
        await events.AddAsync(stored.UserId, SecurityEventTypes.Logout, ctx);
    }

    public async Task<ServiceResult<UserDto>> VerifyEmailAsync(VerifyEmailRequest request, ClientContext ctx)
    {
        var result = await identity.ConfirmEmailAsync(request.Email, request.Token);
        if (result.Succeeded) await events.AddAsync(result.Value!.Id, SecurityEventTypes.EmailVerified, ctx);
        return result;
    }

    public async Task<ServiceResult<bool>> ResendVerificationAsync(string userId)
    {
        var user = await identity.GetUserAsync(userId);
        if (user is null) return ServiceResult<bool>.Fail(ErrorKind.Unauthorized, "Not signed in.");
        if (user.EmailConfirmed) return ServiceResult<bool>.Ok(false);
        await SendVerificationEmailAsync(user.Email);
        return ServiceResult<bool>.Ok(true);
    }

    public async Task ForgotPasswordAsync(ForgotPasswordRequest request, ClientContext ctx)
    {
        // Always behaves the same to the caller so accounts cannot be enumerated.
        var token = await identity.GeneratePasswordResetTokenAsync(request.Email);
        if (token is null) return;
        var link = $"{options.FrontendUrl}/forgot-password?email={Uri.EscapeDataString(request.Email)}&token={Uri.EscapeDataString(token)}";
        await email.SendAsync(request.Email, "Reset your API Vault password",
            $"Use this link to reset your password: {link}\n\n" +
            "To keep your secrets you will need your recovery key. Without it, you can still reset, but your stored secrets will be erased.");
    }

    public async Task<ServiceResult<RecoveryMaterialResponse>> GetRecoveryMaterialAsync(RecoveryMaterialRequest request)
    {
        var invalid = ServiceResult<RecoveryMaterialResponse>.Fail(ErrorKind.Validation, "This reset link is invalid or has expired.");
        var userId = await identity.VerifyPasswordResetTokenAsync(request.Email, request.Token);
        if (userId is null) return invalid;
        var vault = await vaults.GetByUserAsync(userId);
        if (vault is null) return invalid;
        var recovery = (await vaults.GetWrappersAsync(vault.Id)).FirstOrDefault(w => w.WrapperType == WrapperTypes.Recovery);
        return ServiceResult<RecoveryMaterialResponse>.Ok(
            new RecoveryMaterialResponse(vault.Id, recovery is null ? null : VaultFactory.ToResponse(recovery)));
    }

    /// <summary>
    /// Resets the password. Vault keys change only in the way the request states explicitly: re-wrapped (same vault key,
    /// secrets kept) or replaced (old vault and secrets erased). There is no path that silently replaces vault keys.
    /// </summary>
    public async Task<ServiceResult<UserDto>> ResetPasswordAsync(ResetPasswordRequest request, ClientContext ctx)
    {
        if ((request.KeyUpdate is null) == (request.ReplacementVault is null))
            return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Password reset failed.", ["Provide either re-wrapped vault keys or a replacement vault."]);
        var errors = request.KeyUpdate is not null
            ? VaultValidator.ValidateKeyUpdate(request.KeyUpdate)
            : VaultValidator.ValidateCreate(request.ReplacementVault!);
        if (errors.Count > 0) return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Password reset failed.", errors);

        var result = await transactions.InTransactionAsync(async () =>
        {
            var reset = await identity.ResetPasswordAsync(request.Email, request.Token, request.NewPassword);
            if (!reset.Succeeded) return reset;
            var userId = reset.Value!.Id;
            var vault = await vaults.GetByUserAsync(userId);
            var now = DateTime.UtcNow;

            if (request.KeyUpdate is { } k)
            {
                if (vault is null) return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Password reset failed.", ["No vault to re-key."]);
                vault.KdfSalt = k.KdfSalt;
                vault.KdfParameters = k.KdfParameters;
                await vaults.UpsertWrapperAsync(vault, VaultFactory.Wrapper(vault.Id, k.PasswordWrapper, now));
            }
            else
            {
                var replacement = request.ReplacementVault!;
                if (vault is not null) await vaults.DeleteAsync(vault); // explicit, user-confirmed erase
                if (await vaults.ExistsAsync(replacement.Id))
                    return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Password reset failed.", ["Invalid vault id."]);
                await vaults.AddAsync(VaultFactory.Build(userId, replacement, now));
            }
            return reset;
        });
        if (!result.Succeeded) return result;

        await refreshTokens.RevokeAllForUserAsync(result.Value!.Id);
        await events.AddAsync(result.Value.Id, SecurityEventTypes.PasswordReset, ctx);
        if (request.ReplacementVault is not null) await events.AddAsync(result.Value.Id, SecurityEventTypes.VaultReplaced, ctx);
        return result;
    }

    public Task<UserDto?> GetCurrentUserAsync(string userId) => identity.GetUserAsync(userId);

    private async Task<AuthResult> IssueAsync(UserDto user, RefreshToken? rotating)
    {
        var (access, accessExpires) = tokens.CreateAccessToken(user);
        var raw = tokens.GenerateRefreshToken();
        var now = DateTime.UtcNow;
        var replacement = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            TokenHash = tokens.HashToken(raw),
            CreatedAt = now,
            ExpiresAt = now.Add(tokens.RefreshTokenLifetime),
        };
        if (rotating is null) await refreshTokens.AddAsync(replacement);
        else await refreshTokens.RotateAsync(rotating, replacement);

        return new AuthResult(new AuthResponse(access, accessExpires, user), raw, replacement.ExpiresAt);
    }

    private async Task SendVerificationEmailAsync(string address)
    {
        var token = await identity.GenerateEmailConfirmationTokenAsync(address);
        if (token is null) return;
        var link = $"{options.FrontendUrl}/verify-email?email={Uri.EscapeDataString(address)}&token={Uri.EscapeDataString(token)}";
        await email.SendAsync(address, "Verify your API Vault email",
            $"Confirm your email address for API Vault by opening this link:\n\n{link}\n\n" +
            "If you didn't create an account, you can ignore this email.");
    }
}
