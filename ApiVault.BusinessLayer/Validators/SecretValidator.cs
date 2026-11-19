using ApiVault.Core.Constants;
using ApiVault.Core.DTOs;

namespace ApiVault.BusinessLayer.Validators;

/// <summary>Validates metadata and the structure of encrypted payloads. The server cannot (and must not) inspect plaintext.</summary>
public static class SecretValidator
{
    public static List<string> ValidateCreate(CreateSecretRequest r)
    {
        var errors = new List<string>();
        if (r.Id == Guid.Empty) errors.Add("Secret id is required.");
        if (r.VaultId == Guid.Empty) errors.Add("Vault id is required.");
        ValidateMetadata(r.Name, r.Description, r.SecretType, r.Provider, r.Environment, r.TagIds, errors);
        ValidatePayload(r.EncryptedPayload, r.Nonce, r.AuthTag, r.EncryptionVersion, errors);
        return errors;
    }

    public static List<string> ValidateUpdate(UpdateSecretRequest r)
    {
        var errors = new List<string>();
        ValidateMetadata(r.Name, r.Description, r.SecretType, r.Provider, r.Environment, r.TagIds, errors);
        var anyPayload = r.EncryptedPayload is not null || r.Nonce is not null || r.AuthTag is not null || r.EncryptionVersion is not null;
        if (anyPayload)
            ValidatePayload(r.EncryptedPayload, r.Nonce, r.AuthTag, r.EncryptionVersion ?? 0, errors);
        return errors;
    }

    public static List<string> ValidateVersion(CreateSecretVersionRequest r)
    {
        var errors = new List<string>();
        ValidatePayload(r.EncryptedPayload, r.Nonce, r.AuthTag, r.EncryptionVersion, errors);
        return errors;
    }

    public static List<string> ValidateTagName(string? name)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(name) || name.Trim().Length > 100) errors.Add("Tag name is required (max 100 characters).");
        return errors;
    }

    private static void ValidateMetadata(string? name, string? description, string? type, string? provider,
        string? environment, IReadOnlyList<Guid>? tagIds, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200) errors.Add("Name is required (max 200 characters).");
        if (description is { Length: > 500 }) errors.Add("Description must be at most 500 characters.");
        if (type is null || !SecretTypes.All.Contains(type)) errors.Add("Secret type must be ApiKey, Password or SecureNote.");
        if (provider is { Length: > 150 }) errors.Add("Provider must be at most 150 characters.");
        if (environment is { Length: > 30 }) errors.Add("Environment must be at most 30 characters.");
        if (tagIds is { Count: > SecretLimits.MaxTagsPerSecret }) errors.Add($"At most {SecretLimits.MaxTagsPerSecret} tags per secret.");
    }

    private static void ValidatePayload(byte[]? payload, byte[]? nonce, byte[]? tag, int version, List<string> errors)
    {
        if (payload is null || payload.Length == 0 || payload.Length > SecretLimits.MaxPayloadBytes)
            errors.Add($"Encrypted payload is required (max {SecretLimits.MaxPayloadBytes} bytes).");
        if (nonce is null || nonce.Length != CryptoConstants.NonceLength)
            errors.Add($"Nonce must be {CryptoConstants.NonceLength} bytes.");
        if (tag is null || tag.Length != CryptoConstants.AuthTagLength)
            errors.Add($"Auth tag must be {CryptoConstants.AuthTagLength} bytes.");
        if (version < 1) errors.Add("Encryption version must be at least 1.");
    }
}
