namespace ApiVault.Core.DTOs;

public enum ErrorKind { None, Validation, NotFound, Conflict, Unauthorized, Forbidden }

public class ServiceResult<T>
{
    public T? Value { get; init; }
    public ErrorKind Error { get; init; }
    public string? Message { get; init; }
    public IReadOnlyList<string> Details { get; init; } = [];
    public bool Succeeded => Error == ErrorKind.None;

    public static ServiceResult<T> Ok(T value) => new() { Value = value };

    public static ServiceResult<T> Fail(ErrorKind kind, string message, IEnumerable<string>? details = null) =>
        new() { Error = kind, Message = message, Details = details?.ToList() ?? [] };
}

public record ClientContext(string? IpAddress, string? UserAgent);

public record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int TotalCount);
