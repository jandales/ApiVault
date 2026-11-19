using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using ApiVault.Infrastructure.Data;
using ApiVault.Tests.IntegrationTests;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiVault.Tests.SecurityTests;

public class AuthAndVaultSecurityTests : IClassFixture<ApiFactory>
{
    private const string NewAuthKey = "bmV3LWF1dGgta2V5LWFmdGVyLXJlc2V0LTAxMjM0NTY=";
    private readonly ApiFactory _f;
    public AuthAndVaultSecurityTests(ApiFactory f) => _f = f;

    private async Task<string> ResetTokenAsync(string email)
    {
        var http = TestClient.NewHttp(_f);
        Assert.Equal(HttpStatusCode.Accepted, (await http.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email })).StatusCode);
        var mail = _f.Email.Sent.Last(m => m.To == email && m.Subject.Contains("Reset"));
        return Uri.UnescapeDataString(Regex.Match(mail.Body, "token=([^\\s&]+)").Groups[1].Value);
    }

    // ------------------------------------------------------------ authentication

    [Fact]
    public async Task Protected_endpoints_require_authentication()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Register_login_me_and_wrong_password()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var me = await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/auth/me");
        Assert.Equal(u.Email, me.GetProperty("email").GetString());

        var bad = await u.LoginAsync("d3JvbmctYXV0aC1rZXktMDEyMzQ1Njc4OWFiY2RlZjAx");
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
    }

    [Fact]
    public async Task Email_verification_link_confirms_the_account_and_resend_stops_after()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        Assert.False((await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/auth/me")).GetProperty("emailConfirmed").GetBoolean());

        // Resend while unverified sends a fresh link.
        var before = _f.Email.Sent.Count(m => m.To == u.Email && m.Subject.Contains("Verify"));
        Assert.Equal(HttpStatusCode.Accepted, (await u.Http.PostAsync("/api/v1/auth/resend-verification", null)).StatusCode);
        Assert.Equal(before + 1, _f.Email.Sent.Count(m => m.To == u.Email && m.Subject.Contains("Verify")));

        var mail = _f.Email.Sent.Last(m => m.To == u.Email && m.Subject.Contains("Verify"));
        Assert.Contains("/verify-email?email=", mail.Body);
        var token = Uri.UnescapeDataString(Regex.Match(mail.Body, "token=([^\\s&]+)").Groups[1].Value);

        var http = TestClient.NewHttp(_f); // works without being signed in
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/api/v1/auth/verify-email", new { email = u.Email, token = "bogus" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await http.PostAsJsonAsync("/api/v1/auth/verify-email", new { email = u.Email, token })).StatusCode);
        Assert.True((await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/auth/me")).GetProperty("emailConfirmed").GetBoolean());

        // Already verified: resend is accepted but sends nothing.
        var count = _f.Email.Sent.Count(m => m.To == u.Email);
        Assert.Equal(HttpStatusCode.Accepted, (await u.Http.PostAsync("/api/v1/auth/resend-verification", null)).StatusCode);
        Assert.Equal(count, _f.Email.Sent.Count(m => m.To == u.Email));
    }

    [Fact]
    public async Task Resend_verification_requires_sign_in()
    {
        _f.EnsureDatabase();
        Assert.Equal(HttpStatusCode.Unauthorized, (await TestClient.NewHttp(_f).PostAsync("/api/v1/auth/resend-verification", null)).StatusCode);
    }

    [Fact]
    public async Task Server_rejects_values_too_short_to_be_a_derived_key()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var res = await http.PostAsJsonAsync("/api/v1/auth/register",
            new { email = $"raw-{Guid.NewGuid():N}@example.com", password = "MyRawPassword1!", vault = TestClient.NewVaultRequest() });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Registration_creates_account_and_vault_atomically()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var email = $"atomic-{Guid.NewGuid():N}@example.com";

        // Invalid vault material: no account must be left behind.
        var bad = new
        {
            email, password = TestClient.Password,
            vault = new { id = Guid.NewGuid(), name = "Personal", kdfAlgorithm = "Argon2id", kdfSalt = new byte[16],
                kdfParameters = "{\"v\":1,\"m\":8,\"t\":1,\"p\":1}", encryptionAlgorithm = "AES-256-GCM", keyVersion = 1,
                passwordWrapper = TestClient.Wrapper("Password") },
        };
        Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/api/v1/auth/register", bad)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = TestClient.Password })).StatusCode);

        // The same email can then register properly.
        var u = await TestClient.RegisterAndLoginAsync(_f, email);
        var vaults = await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/vaults");
        Assert.Equal(1, vaults.GetProperty("totalCount").GetInt32());
        Assert.Equal(u.VaultId, vaults.GetProperty("items")[0].GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task Registration_without_vault_material_is_rejected()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var res = await http.PostAsJsonAsync("/api/v1/auth/register", new { email = $"nv-{Guid.NewGuid():N}@example.com", password = TestClient.Password });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Prelogin_returns_account_salt_and_a_stable_decoy_for_unknown_emails()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var http = TestClient.NewHttp(_f);
        var real = await (await http.PostAsJsonAsync("/api/v1/auth/prelogin", new { email = u.Email })).Content.ReadFromJsonAsync<JsonElement>();
        var vault = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}");
        Assert.Equal(vault.GetProperty("kdfSalt").GetString(), real.GetProperty("kdfSalt").GetString());

        async Task<string?> Decoy(string email) =>
            (await (await http.PostAsJsonAsync("/api/v1/auth/prelogin", new { email })).Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("kdfSalt").GetString();
        var d1 = await Decoy("nobody@example.com");
        Assert.Equal(d1, await Decoy("NOBODY@example.com ")); // stable, case-insensitive
        Assert.NotEqual(d1, await Decoy("someone-else@example.com"));
        Assert.Equal(16, Convert.FromBase64String(d1!).Length); // looks like a real salt
    }

    [Fact]
    public async Task Refresh_rotates_token_and_reuse_revokes_all_sessions()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var first = u.RefreshCookie!;

        Assert.Equal(HttpStatusCode.OK, (await u.RefreshAsync()).StatusCode);
        var second = u.RefreshCookie!;
        Assert.NotEqual(first, second);

        Assert.Equal(HttpStatusCode.Unauthorized, (await u.RefreshAsync(first)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await u.RefreshAsync(second)).StatusCode);
    }

    [Fact]
    public async Task Logout_revokes_refresh_token()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        Assert.Equal(HttpStatusCode.NoContent, (await u.LogoutAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await u.RefreshAsync()).StatusCode);
    }

    [Fact]
    public async Task Refresh_tokens_are_stored_hashed_only()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var hashes = await db.RefreshTokens.Where(t => t.UserId == u.UserId).Select(t => t.TokenHash).ToListAsync();
        Assert.NotEmpty(hashes);
        Assert.DoesNotContain(u.RefreshCookie!, hashes);
    }

    // ------------------------------------------------------------ vault

    [Fact]
    public async Task Vault_persists_only_encrypted_material_and_returns_wrappers()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var wrappers = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}/key-wrappers");
        var types = wrappers.EnumerateArray().Select(w => w.GetProperty("wrapperType").GetString()!).OrderBy(x => x).ToArray();
        Assert.Equal(new[] { "Password", "Recovery" }, types);
        var vault = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}");
        Assert.Equal("Argon2id", vault.GetProperty("kdfAlgorithm").GetString());
    }

    [Fact]
    public async Task Vault_cannot_be_created_or_deleted_directly()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await u.Http.PostAsJsonAsync("/api/v1/vaults", TestClient.NewVaultRequest())).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await u.Http.DeleteAsync($"/api/v1/vaults/{u.VaultId}")).StatusCode);
    }

    [Fact]
    public async Task User_cannot_access_another_users_vault()
    {
        var a = await TestClient.RegisterAndLoginAsync(_f);
        var b = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = a.VaultId;

        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.GetAsync($"/api/v1/vaults/{vaultId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.GetAsync($"/api/v1/vaults/{vaultId}/key-wrappers")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PostAsJsonAsync($"/api/v1/vaults/{vaultId}/key-wrappers", TestClient.Wrapper("Password"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PutAsJsonAsync($"/api/v1/vaults/{vaultId}", new { name = "pwned" })).StatusCode);

        var list = await b.Http.GetFromJsonAsync<JsonElement>("/api/v1/vaults");
        Assert.Equal(1, list.GetProperty("totalCount").GetInt32());
        Assert.Equal(b.VaultId, list.GetProperty("items")[0].GetProperty("id").GetGuid());
        Assert.Equal(HttpStatusCode.OK, (await a.Http.GetAsync($"/api/v1/vaults/{vaultId}")).StatusCode);
    }

    [Fact]
    public async Task Duplicate_vault_id_at_registration_is_rejected()
    {
        var a = await TestClient.RegisterAndLoginAsync(_f);
        var http = TestClient.NewHttp(_f);
        var res = await http.PostAsJsonAsync("/api/v1/auth/register",
            new { email = $"dup-{Guid.NewGuid():N}@example.com", password = TestClient.Password, vault = TestClient.NewVaultRequest(a.VaultId) });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Theory]
    [InlineData(8)]
    [InlineData(16)]
    public async Task Malformed_wrapper_is_rejected(int nonceLength)
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var res = await u.Http.PostAsJsonAsync($"/api/v1/vaults/{u.VaultId}/key-wrappers", TestClient.Wrapper("Password", nonceLength));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Wrapper_upsert_keeps_a_single_active_wrapper_per_type()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        Assert.Equal(HttpStatusCode.OK, (await u.Http.PostAsJsonAsync($"/api/v1/vaults/{u.VaultId}/key-wrappers", TestClient.Wrapper("Password"))).StatusCode);
        var wrappers = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}/key-wrappers");
        Assert.Equal(2, wrappers.GetArrayLength());
    }

    // ------------------------------------------------------------ password reset

    [Fact]
    public async Task Recovery_material_requires_a_valid_reset_token()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var http = TestClient.NewHttp(_f);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await http.PostAsJsonAsync("/api/v1/auth/recovery", new { email = u.Email, token = "bogus" })).StatusCode);

        var token = await ResetTokenAsync(u.Email);
        var ok = await (await http.PostAsJsonAsync("/api/v1/auth/recovery", new { email = u.Email, token })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(u.VaultId, ok.GetProperty("vaultId").GetGuid());
        Assert.Equal("Recovery", ok.GetProperty("recoveryWrapper").GetProperty("wrapperType").GetString());
    }

    [Fact]
    public async Task Reset_must_state_explicitly_what_happens_to_vault_keys()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var token = await ResetTokenAsync(u.Email);
        var http = TestClient.NewHttp(_f);

        var neither = await http.PostAsJsonAsync("/api/v1/auth/reset-password", new { email = u.Email, token, newPassword = NewAuthKey });
        Assert.Equal(HttpStatusCode.BadRequest, neither.StatusCode);

        var both = await http.PostAsJsonAsync("/api/v1/auth/reset-password", new
        {
            email = u.Email, token, newPassword = NewAuthKey,
            keyUpdate = new { kdfSalt = RandomNumberGenerator.GetBytes(16), kdfParameters = "{\"v\":1,\"m\":65536,\"t\":3,\"p\":1}", passwordWrapper = TestClient.Wrapper("Password") },
            replacementVault = TestClient.NewVaultRequest(),
        });
        Assert.Equal(HttpStatusCode.BadRequest, both.StatusCode);

        // Nothing changed: the old password still works.
        Assert.Equal(HttpStatusCode.OK, (await u.LoginAsync()).StatusCode);
    }

    [Fact]
    public async Task Reset_with_recovery_rewrap_keeps_vault_recovery_wrapper_and_secrets()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var secret = await u.Http.PostAsJsonAsync("/api/v1/secrets", new
        {
            id = Guid.NewGuid(), vaultId = u.VaultId, name = "keep me", secretType = "ApiKey",
            encryptedPayload = RandomNumberGenerator.GetBytes(40), nonce = RandomNumberGenerator.GetBytes(12),
            authTag = RandomNumberGenerator.GetBytes(16), encryptionVersion = 1,
        });
        Assert.Equal(HttpStatusCode.Created, secret.StatusCode);
        var before = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}/key-wrappers");
        string Wrapper(JsonElement list, string type) =>
            list.EnumerateArray().First(w => w.GetProperty("wrapperType").GetString() == type).GetProperty("encryptedVaultKey").GetString()!;

        var token = await ResetTokenAsync(u.Email);
        var newSalt = RandomNumberGenerator.GetBytes(16);
        var reset = await TestClient.NewHttp(_f).PostAsJsonAsync("/api/v1/auth/reset-password", new
        {
            email = u.Email, token, newPassword = NewAuthKey,
            keyUpdate = new { kdfSalt = newSalt, kdfParameters = "{\"v\":1,\"m\":65536,\"t\":3,\"p\":1}", passwordWrapper = TestClient.Wrapper("Password") },
        });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await u.RefreshAsync()).StatusCode); // old sessions revoked
        Assert.Equal(HttpStatusCode.OK, (await u.LoginAsync(NewAuthKey)).StatusCode);

        var after = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}/key-wrappers");
        Assert.Equal(Wrapper(before, "Recovery"), Wrapper(after, "Recovery"));   // same vault key, same recovery wrapper
        Assert.NotEqual(Wrapper(before, "Password"), Wrapper(after, "Password")); // re-wrapped for the new password
        var vault = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/vaults/{u.VaultId}");
        Assert.Equal(Convert.ToBase64String(newSalt), vault.GetProperty("kdfSalt").GetString());
        Assert.Equal(1, (await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/secrets")).GetProperty("totalCount").GetInt32());
    }

    [Fact]
    public async Task Reset_with_replacement_vault_erases_old_vault_and_secrets()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        await u.Http.PostAsJsonAsync("/api/v1/secrets", new
        {
            id = Guid.NewGuid(), vaultId = u.VaultId, name = "lost", secretType = "ApiKey",
            encryptedPayload = RandomNumberGenerator.GetBytes(40), nonce = RandomNumberGenerator.GetBytes(12),
            authTag = RandomNumberGenerator.GetBytes(16), encryptionVersion = 1,
        });

        var token = await ResetTokenAsync(u.Email);
        var newVaultId = Guid.NewGuid();
        var reset = await TestClient.NewHttp(_f).PostAsJsonAsync("/api/v1/auth/reset-password", new
        {
            email = u.Email, token, newPassword = NewAuthKey, replacementVault = TestClient.NewVaultRequest(newVaultId),
        });
        Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await u.LoginAsync(NewAuthKey)).StatusCode);
        var vaults = await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/vaults");
        Assert.Equal(1, vaults.GetProperty("totalCount").GetInt32());
        Assert.Equal(newVaultId, vaults.GetProperty("items")[0].GetProperty("id").GetGuid());
        Assert.Equal(0, (await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/secrets")).GetProperty("totalCount").GetInt32());

        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.False(await db.Vaults.AnyAsync(v => v.Id == u.VaultId));
    }

    [Fact]
    public async Task Failed_reset_changes_nothing()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var token = await ResetTokenAsync(u.Email);
        // Valid shape but a too-short new password: Identity rejects it, so the vault must not be replaced either.
        var reset = await TestClient.NewHttp(_f).PostAsJsonAsync("/api/v1/auth/reset-password", new
        {
            email = u.Email, token, newPassword = "short", replacementVault = TestClient.NewVaultRequest(),
        });
        Assert.Equal(HttpStatusCode.BadRequest, reset.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await u.LoginAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await u.Http.GetAsync($"/api/v1/vaults/{u.VaultId}")).StatusCode);
    }

    [Fact]
    public async Task Forgot_password_response_does_not_reveal_whether_account_exists()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var res = await http.PostAsJsonAsync("/api/v1/auth/forgot-password", new { email = "nobody@example.com" });
        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
    }
}
