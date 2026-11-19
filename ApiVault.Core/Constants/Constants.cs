namespace ApiVault.Core.Constants;

public static class WrapperTypes
{
    public const string Password = "Password";
    public const string Recovery = "Recovery";
    public static readonly string[] All = [Password, Recovery];
}

public static class CryptoConstants
{
    public const string KdfAlgorithm = "Argon2id";
    public const string EncryptionAlgorithm = "AES-256-GCM";
    public const int NonceLength = 12;      // 96 bits
    public const int AuthTagLength = 16;    // 128 bits
    public const int VaultKeyLength = 32;   // 256-bit VEK (GCM ciphertext length equals plaintext length)
    public const int MinSaltLength = 16;
    public const int MaxSaltLength = 64;
    public const int MaxKdfParametersLength = 500;
}

public static class SecurityEventTypes
{
    public const string Registered = "Registered";
    public const string LoginSucceeded = "LoginSucceeded";
    public const string LoginFailed = "LoginFailed";
    public const string Logout = "Logout";
    public const string RefreshTokenReuseDetected = "RefreshTokenReuseDetected";
    public const string EmailVerified = "EmailVerified";
    public const string PasswordResetRequested = "PasswordResetRequested";
    public const string PasswordReset = "PasswordReset";
    public const string VaultCreated = "VaultCreated";
    public const string VaultReplaced = "VaultReplaced";
    public const string VaultDeleted = "VaultDeleted";
    public const string KeyWrapperChanged = "KeyWrapperChanged";
}
