using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using ApiVault.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace ApiVault.Infrastructure.Services;

public class IdentityService(UserManager<ApplicationUser> users) : IIdentityService
{
    public async Task<ServiceResult<UserDto>> RegisterAsync(string email, string password)
    {
        var user = new ApplicationUser { UserName = email, Email = email, CreatedAt = DateTime.UtcNow };
        var result = await users.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            var details = result.Errors.Select(e => e.Description).ToList();
            var duplicate = result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
            // Do not reveal that the email is taken.
            return duplicate
                ? ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", ["Unable to register with these details."])
                : ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", details);
        }
        return ServiceResult<UserDto>.Ok(ToDto(user));
    }

    public async Task<ServiceResult<UserDto>> ValidateCredentialsAsync(string email, string password)
    {
        var user = await users.FindByEmailAsync(email);
        if (user is null) return ServiceResult<UserDto>.Fail(ErrorKind.Unauthorized, "Invalid credentials.");
        if (await users.IsLockedOutAsync(user)) return ServiceResult<UserDto>.Fail(ErrorKind.Forbidden, "Locked out.");

        if (!await users.CheckPasswordAsync(user, password))
        {
            await users.AccessFailedAsync(user);
            return ServiceResult<UserDto>.Fail(ErrorKind.Unauthorized, "Invalid credentials.");
        }
        await users.ResetAccessFailedCountAsync(user);
        return ServiceResult<UserDto>.Ok(ToDto(user));
    }

    public async Task<UserDto?> GetUserAsync(string userId)
    {
        var user = await users.FindByIdAsync(userId);
        return user is null ? null : ToDto(user);
    }

    public async Task<string?> FindUserIdByEmailAsync(string email) => (await users.FindByEmailAsync(email))?.Id;

    public async Task<UserDto?> FindByExternalLoginAsync(string provider, string providerKey)
    {
        var user = await users.FindByLoginAsync(provider, providerKey);
        return user is null ? null : ToDto(user);
    }

    public async Task<ServiceResult<UserDto>> LinkExternalLoginAsync(string userId, string provider, string providerKey, bool confirmEmail)
    {
        var user = await users.FindByIdAsync(userId);
        if (user is null) return ServiceResult<UserDto>.Fail(ErrorKind.NotFound, "Account not found.");
        var logins = await users.GetLoginsAsync(user);
        if (!logins.Any(l => l.LoginProvider == provider && l.ProviderKey == providerKey))
        {
            var added = await users.AddLoginAsync(user, new UserLoginInfo(provider, providerKey, provider));
            if (!added.Succeeded) return ServiceResult<UserDto>.Fail(ErrorKind.Conflict, "This Google account is already linked to another user.");
        }
        if (confirmEmail && !user.EmailConfirmed)
        {
            user.EmailConfirmed = true;
            await users.UpdateAsync(user);
        }
        return ServiceResult<UserDto>.Ok(ToDto(user));
    }

    public async Task<ServiceResult<UserDto>> RegisterExternalAsync(string email, string password, string provider, string providerKey)
    {
        var user = new ApplicationUser { UserName = email, Email = email, EmailConfirmed = true, CreatedAt = DateTime.UtcNow };
        var created = await users.CreateAsync(user, password);
        if (!created.Succeeded)
            return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Registration failed.", ["Unable to register with these details."]);
        var linked = await users.AddLoginAsync(user, new UserLoginInfo(provider, providerKey, provider));
        if (!linked.Succeeded) return ServiceResult<UserDto>.Fail(ErrorKind.Conflict, "This Google account is already linked to another user.");
        return ServiceResult<UserDto>.Ok(ToDto(user));
    }

    public async Task<string?> VerifyPasswordResetTokenAsync(string email, string token)
    {
        var user = await users.FindByEmailAsync(email);
        if (user is null || string.IsNullOrEmpty(token)) return null;
        var ok = await users.VerifyUserTokenAsync(user, users.Options.Tokens.PasswordResetTokenProvider,
            UserManager<ApplicationUser>.ResetPasswordTokenPurpose, token);
        return ok ? user.Id : null;
    }

    public async Task<string?> GenerateEmailConfirmationTokenAsync(string email)
    {
        var user = await users.FindByEmailAsync(email);
        return user is null ? null : await users.GenerateEmailConfirmationTokenAsync(user);
    }

    public async Task<ServiceResult<UserDto>> ConfirmEmailAsync(string email, string token)
    {
        var user = await users.FindByEmailAsync(email);
        if (user is null) return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Invalid verification link.");
        var result = await users.ConfirmEmailAsync(user, token);
        return result.Succeeded
            ? ServiceResult<UserDto>.Ok(ToDto(user))
            : ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Invalid verification link.");
    }

    public async Task<string?> GeneratePasswordResetTokenAsync(string email)
    {
        var user = await users.FindByEmailAsync(email);
        return user is null ? null : await users.GeneratePasswordResetTokenAsync(user);
    }

    public async Task<ServiceResult<UserDto>> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await users.FindByEmailAsync(email);
        if (user is null) return ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Invalid reset link.");
        var result = await users.ResetPasswordAsync(user, token, newPassword);
        return result.Succeeded
            ? ServiceResult<UserDto>.Ok(ToDto(user))
            : ServiceResult<UserDto>.Fail(ErrorKind.Validation, "Password reset failed.",
                result.Errors.Where(e => !e.Code.StartsWith("InvalidToken")).Select(e => e.Description));
    }

    private static UserDto ToDto(ApplicationUser u) => new(u.Id, u.Email ?? string.Empty, u.EmailConfirmed);
}
