using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApiVault.API.Extensions;
using ApiVault.BusinessLayer.Implementation;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;

namespace ApiVault.API.Controllers;

/// <summary>
/// "Continue with Google" via the authorization-code flow with PKCE, handled entirely on the server.
/// Signing in with Google proves identity only; secrets still require the encryption password in the browser.
/// </summary>
[ApiController]
[Route("api/v1/auth/google")]
public class GoogleAuthController(
    IGoogleAuthClient google,
    IAuthService auth,
    IDataProtectionProvider dataProtection,
    AuthOptions authOptions,
    ILogger<GoogleAuthController> logger) : ControllerBase
{
    private const string FlowCookie = "av_google_flow";
    private const string FlowCookiePath = "/api/v1/auth/google";
    private static readonly TimeSpan FlowLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(15);

    private ITimeLimitedDataProtector FlowProtector => dataProtection.CreateProtector("ApiVault.GoogleFlow.v1").ToTimeLimitedDataProtector();
    private ITimeLimitedDataProtector TicketProtector => dataProtection.CreateProtector("ApiVault.GoogleSignupTicket.v1").ToTimeLimitedDataProtector();

    private sealed record FlowState(string State, string CodeVerifier, string Nonce);

    /// <summary>Starts sign-in: stores state, PKCE verifier and nonce in an encrypted cookie, then redirects to Google.</summary>
    [HttpGet("start"), EnableRateLimiting("auth")]
    public IActionResult Start()
    {
        if (!google.IsConfigured) return NotFound();

        var flow = new FlowState(Random(32), Random(64), Random(32));
        Response.Cookies.Append(FlowCookie, FlowProtector.Protect(JsonSerializer.Serialize(flow), FlowLifetime), new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax, // must survive the top-level redirect back from accounts.google.com
            Path = FlowCookiePath,
            MaxAge = FlowLifetime,
            IsEssential = true,
        });

        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(flow.CodeVerifier)));
        return Redirect(google.BuildAuthorizationUrl(flow.State, challenge, flow.Nonce));
    }

    /// <summary>Google redirects here. Verifies state, exchanges the code, then signs in or hands off to account setup.</summary>
    [HttpGet("callback"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Callback([FromQuery] string? code, [FromQuery] string? state, [FromQuery] string? error)
    {
        var flowCookie = Request.Cookies[FlowCookie];
        Response.Cookies.Delete(FlowCookie, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = FlowCookiePath });

        if (!google.IsConfigured) return NotFound();
        if (!string.IsNullOrEmpty(error)) return ToFrontend("cancelled");
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || string.IsNullOrEmpty(flowCookie)) return ToFrontend("error");

        FlowState? flow;
        try
        {
            flow = JsonSerializer.Deserialize<FlowState>(FlowProtector.Unprotect(flowCookie));
        }
        catch (CryptographicException)
        {
            return ToFrontend("error"); // tampered or expired
        }
        if (flow is null || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(flow.State), Encoding.ASCII.GetBytes(state)))
            return ToFrontend("error");

        var identity = await google.ExchangeCodeAsync(code, flow.CodeVerifier, flow.Nonce, HttpContext.RequestAborted);
        if (identity is null) return ToFrontend("error");

        var outcome = await auth.ExternalSignInAsync(identity, HttpContext.GetClientContext());
        if (!outcome.Succeeded)
        {
            logger.LogInformation("Google sign-in refused: {Reason}", outcome.Message);
            return ToFrontend(outcome.Error == ErrorKind.Validation ? "unverified" : "error");
        }

        if (outcome.Value!.SignedIn is { } signedIn)
        {
            RefreshCookie.Set(Response, signedIn);
            return ToFrontend("signed-in");
        }

        // New user: the browser must create the encryption keys. Hand over a short-lived signed ticket in the URL
        // fragment, which browsers never send to servers or put in Referer headers.
        var ticket = TicketProtector.Protect(JsonSerializer.Serialize(outcome.Value.NeedsSetup), TicketLifetime);
        return Redirect($"{authOptions.FrontendUrl}/auth/google?status=setup#ticket={Uri.EscapeDataString(ticket)}&email={Uri.EscapeDataString(identity.Email)}");
    }

    /// <summary>Finishes a Google sign-up with browser-generated key material and signs the user in.</summary>
    [HttpPost("register"), EnableRateLimiting("auth")]
    public async Task<IActionResult> Register(GoogleRegisterRequest request)
    {
        if (!google.IsConfigured) return NotFound();

        ExternalIdentity? identity;
        try
        {
            identity = JsonSerializer.Deserialize<ExternalIdentity>(TicketProtector.Unprotect(request.Ticket ?? string.Empty));
        }
        catch (CryptographicException)
        {
            identity = null;
        }
        if (identity is null)
            return this.ToProblem(ServiceResult<bool>.Fail(ErrorKind.Validation, "This sign-up link has expired. Continue with Google again."));

        var result = await auth.ExternalRegisterAsync(identity, request.Password, request.Vault, HttpContext.GetClientContext());
        if (!result.Succeeded) return this.ToProblem(result);
        RefreshCookie.Set(Response, result.Value!);
        return Ok(result.Value!.Response);
    }

    private RedirectResult ToFrontend(string status) => Redirect($"{authOptions.FrontendUrl}/auth/google?status={status}");

    private static string Random(int bytes) => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(bytes));
}
