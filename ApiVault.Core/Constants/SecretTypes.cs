namespace ApiVault.Core.Constants;

public static class SecretTypes
{
    public const string ApiKey = "ApiKey";
    public const string Password = "Password";
    public const string SecureNote = "SecureNote";
    /// <summary>OAuth / OIDC client credentials (client ID + client secret), both inside the encrypted payload.</summary>
    public const string OAuthClient = "OAuthClient";
    public static readonly string[] All = [ApiKey, Password, SecureNote, OAuthClient];
}

public static class SecretLimits
{
    public const int MaxPayloadBytes = 64 * 1024;
    public const int MaxTagsPerSecret = 20;
    public const int MaxPageSize = 100;
}
