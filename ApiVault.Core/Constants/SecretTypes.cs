namespace ApiVault.Core.Constants;

public static class SecretTypes
{
    public const string ApiKey = "ApiKey";
    public const string Password = "Password";
    public const string SecureNote = "SecureNote";
    public static readonly string[] All = [ApiKey, Password, SecureNote];
}

public static class SecretLimits
{
    public const int MaxPayloadBytes = 64 * 1024;
    public const int MaxTagsPerSecret = 20;
    public const int MaxPageSize = 100;
}
