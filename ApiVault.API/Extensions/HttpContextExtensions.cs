using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using ApiVault.Core.DTOs;
using Microsoft.AspNetCore.Mvc;

namespace ApiVault.API.Extensions;

public static class HttpContextExtensions
{
    /// <summary>The user id always comes from the validated token, never from the request body or route.</summary>
    public static string GetUserId(this ClaimsPrincipal user) =>
        user.FindFirstValue(JwtRegisteredClaimNames.Sub)
        ?? user.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new InvalidOperationException("Authenticated principal has no subject claim.");

    public static ClientContext GetClientContext(this HttpContext http) =>
        new(http.Connection.RemoteIpAddress?.ToString(), http.Request.Headers.UserAgent.ToString());

    public static IActionResult ToProblem<T>(this ControllerBase controller, ServiceResult<T> result)
    {
        var status = result.Error switch
        {
            ErrorKind.Validation => StatusCodes.Status400BadRequest,
            ErrorKind.NotFound => StatusCodes.Status404NotFound,
            ErrorKind.Conflict => StatusCodes.Status409Conflict,
            ErrorKind.Unauthorized => StatusCodes.Status401Unauthorized,
            ErrorKind.Forbidden => StatusCodes.Status403Forbidden,
            _ => StatusCodes.Status500InternalServerError,
        };
        var problem = new ProblemDetails { Status = status, Title = result.Message };
        if (result.Details.Count > 0) problem.Extensions["errors"] = result.Details;
        return new ObjectResult(problem) { StatusCode = status };
    }
}
