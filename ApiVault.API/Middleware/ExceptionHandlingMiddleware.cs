using Microsoft.AspNetCore.Mvc;

namespace ApiVault.API.Middleware;

/// <summary>
/// Converts unhandled exceptions to a generic ProblemDetails. Logs only the exception type and trace id —
/// never request bodies, which may contain credentials or encrypted material.
/// </summary>
public class ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            logger.LogError("Unhandled {ExceptionType} on {Method} {Path} (trace {TraceId})",
                ex.GetType().Name, context.Request.Method, context.Request.Path, context.TraceIdentifier);
            if (context.Response.HasStarted) throw;
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new ProblemDetails
            {
                Status = 500,
                Title = "An unexpected error occurred.",
                Extensions = { ["traceId"] = context.TraceIdentifier },
            });
        }
    }
}
