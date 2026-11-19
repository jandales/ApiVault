using ApiVault.API.Extensions;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace ApiVault.API.Controllers;

[ApiController]
[Route("api/v1/auth")]
public class AuthController(IAuthService auth) : ControllerBase
{
    private const string RefreshCookie = "av_refresh";
    private const string RefreshCookiePath = "/api/v1/auth";

    [HttpPost("prelogin"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Prelogin(PreloginRequest request) => Ok(await auth.PreloginAsync(request));

    [HttpPost("recovery"), EnableRateLimiting("auth")]
    public async Task<IActionResult> RecoveryMaterial(RecoveryMaterialRequest request)
    {
        var result = await auth.GetRecoveryMaterialAsync(request);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPost("register"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var result = await auth.RegisterAsync(request, HttpContext.GetClientContext());
        return result.Succeeded ? StatusCode(StatusCodes.Status201Created, result.Value) : this.ToProblem(result);
    }

    [HttpPost("login"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var result = await auth.LoginAsync(request, HttpContext.GetClientContext());
        if (!result.Succeeded) return this.ToProblem(result);
        SetRefreshCookie(result.Value!);
        return Ok(result.Value!.Response);
    }

    [HttpPost("refresh"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Refresh()
    {
        var result = await auth.RefreshAsync(Request.Cookies[RefreshCookie], HttpContext.GetClientContext());
        if (!result.Succeeded)
        {
            ClearRefreshCookie();
            return this.ToProblem(result);
        }
        SetRefreshCookie(result.Value!);
        return Ok(result.Value!.Response);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await auth.LogoutAsync(Request.Cookies[RefreshCookie], HttpContext.GetClientContext());
        ClearRefreshCookie();
        return NoContent();
    }

    [HttpPost("verify-email"), EnableRateLimiting("auth")]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest request)
    {
        var result = await auth.VerifyEmailAsync(request, HttpContext.GetClientContext());
        return result.Succeeded ? NoContent() : this.ToProblem(result);
    }

    [HttpPost("resend-verification"), Authorize, EnableRateLimiting("auth")]
    public async Task<IActionResult> ResendVerification()
    {
        var result = await auth.ResendVerificationAsync(User.GetUserId());
        return result.Succeeded ? Accepted() : this.ToProblem(result);
    }

    [HttpPost("forgot-password"), EnableRateLimiting("auth")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest request)
    {
        await auth.ForgotPasswordAsync(request, HttpContext.GetClientContext());
        return Accepted(); // identical response whether or not the account exists
    }

    [HttpPost("reset-password"), EnableRateLimiting("auth")]
    public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
    {
        var result = await auth.ResetPasswordAsync(request, HttpContext.GetClientContext());
        return result.Succeeded ? NoContent() : this.ToProblem(result);
    }

    [HttpGet("me"), Authorize]
    public async Task<IActionResult> Me()
    {
        var user = await auth.GetCurrentUserAsync(User.GetUserId());
        return user is null ? Unauthorized() : Ok(user);
    }

    private void SetRefreshCookie(AuthResult result) =>
        Response.Cookies.Append(RefreshCookie, result.RawRefreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = RefreshCookiePath,
            Expires = result.RefreshExpiresAt,
            IsEssential = true,
        });

    private void ClearRefreshCookie() =>
        Response.Cookies.Delete(RefreshCookie, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = RefreshCookiePath,
        });
}
