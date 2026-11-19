using ApiVault.Core.DTOs;
using ApiVault.Core.Entities;

namespace ApiVault.BusinessLayer.Implementation;

/// <summary>Builds vault entities from validated, browser-produced key material.</summary>
public static class VaultFactory
{
    public static Vault Build(string userId, CreateVaultRequest r, DateTime now)
    {
        var vault = new Vault
        {
            Id = r.Id,
            UserId = userId, // always from the server side, never the request
            Name = r.Name.Trim(),
            Description = r.Description?.Trim(),
            KdfAlgorithm = r.KdfAlgorithm,
            KdfSalt = r.KdfSalt,
            KdfParameters = r.KdfParameters,
            EncryptionAlgorithm = r.EncryptionAlgorithm,
            KeyVersion = r.KeyVersion,
            CreatedAt = now,
        };
        vault.KeyWrappers.Add(Wrapper(vault.Id, r.PasswordWrapper, now));
        if (r.RecoveryWrapper is not null) vault.KeyWrappers.Add(Wrapper(vault.Id, r.RecoveryWrapper, now));
        return vault;
    }

    public static VaultKeyWrapper Wrapper(Guid vaultId, KeyWrapperRequest w, DateTime now) => new()
    {
        Id = Guid.NewGuid(),
        VaultId = vaultId,
        WrapperType = w.WrapperType,
        EncryptedVaultKey = w.EncryptedVaultKey,
        Nonce = w.Nonce,
        AuthTag = w.AuthTag,
        KeyVersion = w.KeyVersion,
        CreatedAt = now,
    };

    public static VaultResponse ToResponse(Vault v) => new(v.Id, v.Name, v.Description, v.KdfAlgorithm, v.KdfSalt,
        v.KdfParameters, v.EncryptionAlgorithm, v.KeyVersion, v.CreatedAt, v.ModifiedAt);

    public static KeyWrapperResponse ToResponse(VaultKeyWrapper w) => new(w.Id, w.VaultId, w.WrapperType,
        w.EncryptedVaultKey, w.Nonce, w.AuthTag, w.KeyVersion, w.CreatedAt);
}
