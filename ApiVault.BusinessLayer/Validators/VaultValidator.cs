using System.Text.Json;
using ApiVault.Core.Constants;
using ApiVault.Core.DTOs;

namespace ApiVault.BusinessLayer.Validators;

/// <summary>Validates the structure of client-supplied encrypted key material. The server cannot verify the ciphertext itself.</summary>
public static class VaultValidator
{
    public static List<string> ValidateCreate(CreateVaultRequest r)
    {
        var errors = new List<string>();
        if (r.Id == Guid.Empty) errors.Add("Vault id is required.");
        ValidateName(r.Name, r.Description, errors);

        if (r.KdfAlgorithm != CryptoConstants.KdfAlgorithm) errors.Add($"KDF algorithm must be {CryptoConstants.KdfAlgorithm}.");
        if (r.EncryptionAlgorithm != CryptoConstants.EncryptionAlgorithm) errors.Add($"Encryption algorithm must be {CryptoConstants.EncryptionAlgorithm}.");
        if (r.KdfSalt is null || r.KdfSalt.Length < CryptoConstants.MinSaltLength || r.KdfSalt.Length > CryptoConstants.MaxSaltLength)
            errors.Add($"KDF salt must be {CryptoConstants.MinSaltLength}-{CryptoConstants.MaxSaltLength} bytes.");
        if (r.KeyVersion < 1) errors.Add("Key version must be at least 1.");
        ValidateKdfParameters(r.KdfParameters, errors);

        if (r.PasswordWrapper is null) errors.Add("Password key wrapper is required.");
        else
        {
            if (r.PasswordWrapper.WrapperType != WrapperTypes.Password) errors.Add("PasswordWrapper must have type Password.");
            errors.AddRange(ValidateWrapper(r.PasswordWrapper));
        }

        if (r.RecoveryWrapper is not null)
        {
            if (r.RecoveryWrapper.WrapperType != WrapperTypes.Recovery) errors.Add("RecoveryWrapper must have type Recovery.");
            errors.AddRange(ValidateWrapper(r.RecoveryWrapper));
        }
        return errors;
    }

    public static List<string> ValidateKeyUpdate(VaultKeyUpdate k)
    {
        var errors = new List<string>();
        if (k.KdfSalt is null || k.KdfSalt.Length < CryptoConstants.MinSaltLength || k.KdfSalt.Length > CryptoConstants.MaxSaltLength)
            errors.Add($"KDF salt must be {CryptoConstants.MinSaltLength}-{CryptoConstants.MaxSaltLength} bytes.");
        ValidateKdfParameters(k.KdfParameters, errors);
        if (k.PasswordWrapper is null) errors.Add("Password key wrapper is required.");
        else
        {
            if (k.PasswordWrapper.WrapperType != WrapperTypes.Password) errors.Add("PasswordWrapper must have type Password.");
            errors.AddRange(ValidateWrapper(k.PasswordWrapper));
        }
        return errors;
    }

    public static List<string> ValidateUpdate(UpdateVaultRequest r)
    {
        var errors = new List<string>();
        ValidateName(r.Name, r.Description, errors);
        return errors;
    }

    public static List<string> ValidateWrapper(KeyWrapperRequest w)
    {
        var errors = new List<string>();
        if (!WrapperTypes.All.Contains(w.WrapperType)) errors.Add("Wrapper type must be Password or Recovery.");
        if (w.EncryptedVaultKey is null || w.EncryptedVaultKey.Length != CryptoConstants.VaultKeyLength)
            errors.Add($"Encrypted vault key must be {CryptoConstants.VaultKeyLength} bytes.");
        if (w.Nonce is null || w.Nonce.Length != CryptoConstants.NonceLength)
            errors.Add($"Nonce must be {CryptoConstants.NonceLength} bytes.");
        if (w.AuthTag is null || w.AuthTag.Length != CryptoConstants.AuthTagLength)
            errors.Add($"Auth tag must be {CryptoConstants.AuthTagLength} bytes.");
        if (w.KeyVersion < 1) errors.Add("Key version must be at least 1.");
        return errors;
    }

    private static void ValidateName(string? name, string? description, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 150) errors.Add("Name is required (max 150 characters).");
        if (description is { Length: > 500 }) errors.Add("Description must be at most 500 characters.");
    }

    /// <summary>Expected shape: {"v":1,"m":65536,"t":3,"p":1} (memory KiB, iterations, parallelism).</summary>
    private static void ValidateKdfParameters(string? json, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > CryptoConstants.MaxKdfParametersLength)
        {
            errors.Add("KDF parameters are required (max 500 characters).");
            return;
        }
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            int Get(string n) => root.TryGetProperty(n, out var e) && e.TryGetInt32(out var v) ? v : -1;
            if (Get("v") < 1) errors.Add("KDF parameters must include a version 'v'.");
            if (Get("m") < 19456) errors.Add("KDF memory 'm' must be at least 19456 KiB.");
            if (Get("t") < 2) errors.Add("KDF iterations 't' must be at least 2.");
            if (Get("p") < 1) errors.Add("KDF parallelism 'p' must be at least 1.");
        }
        catch (JsonException)
        {
            errors.Add("KDF parameters must be valid JSON.");
        }
    }
}
