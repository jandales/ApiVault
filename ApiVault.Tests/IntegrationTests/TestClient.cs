using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;

namespace ApiVault.Tests.IntegrationTests;

/// <summary>Thin helper: one logged-in user with manual refresh-cookie handling.</summary>
public class TestClient
{
    // Stands in for the browser-derived authentication key (base64 of 32 bytes = 44 chars).
    public const string Password = "dGVzdC1hdXRoLWtleS0wMTIzNDU2Nzg5YWJjZGVmMDE=";
    public HttpClient Http { get; }
    public string Email { get; }
    public string? RefreshCookie { get; private set; }
    public string? UserId { get; private set; }
    public Guid VaultId { get; private set; }

    private TestClient(HttpClient http, string email) { Http = http; Email = email; }

    public static HttpClient NewHttp(ApiFactory f) =>
        f.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false, AllowAutoRedirect = false });

    public static async Task<TestClient> RegisterAndLoginAsync(ApiFactory f, string? email = null)
    {
        f.EnsureDatabase();
        email ??= $"user-{Guid.NewGuid():N}@example.com";
        var c = new TestClient(NewHttp(f), email);
        c.VaultId = Guid.NewGuid();
        var reg = await c.Http.PostAsJsonAsync("/api/v1/auth/register", new { email, password = Password, vault = NewVaultRequest(c.VaultId) });
        reg.EnsureSuccessStatusCode();
        await c.LoginAsync();
        return c;
    }

    public async Task<HttpResponseMessage> LoginAsync(string? password = null)
    {
        var res = await Http.PostAsJsonAsync("/api/v1/auth/login", new { email = Email, password = password ?? Password });
        if (res.IsSuccessStatusCode) await ApplyAuthAsync(res);
        return res;
    }

    public async Task<HttpResponseMessage> RefreshAsync(string? cookieOverride = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/refresh");
        req.Headers.Add("Cookie", $"av_refresh={cookieOverride ?? RefreshCookie}");
        var res = await Http.SendAsync(req);
        if (res.IsSuccessStatusCode) await ApplyAuthAsync(res);
        return res;
    }

    public async Task<HttpResponseMessage> LogoutAsync()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        req.Headers.Add("Cookie", $"av_refresh={RefreshCookie}");
        return await Http.SendAsync(req);
    }

    private async Task ApplyAuthAsync(HttpResponseMessage res)
    {
        var body = await res.Content.ReadFromJsonAsync<JsonElement>();
        Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("accessToken").GetString());
        UserId = body.GetProperty("user").GetProperty("id").GetString();
        var set = res.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("av_refresh="));
        RefreshCookie = set.Split(';')[0]["av_refresh=".Length..];
    }

    // ---- Vault payload builders: random bytes stand in for browser-produced ciphertext. ----
    public static object NewVaultRequest(Guid? id = null, bool withRecovery = true) => new
    {
        id = id ?? Guid.NewGuid(),
        name = "Personal",
        description = (string?)null,
        kdfAlgorithm = "Argon2id",
        kdfSalt = RandomNumberGenerator.GetBytes(16),
        kdfParameters = "{\"v\":1,\"m\":65536,\"t\":3,\"p\":1}",
        encryptionAlgorithm = "AES-256-GCM",
        keyVersion = 1,
        passwordWrapper = Wrapper("Password"),
        recoveryWrapper = withRecovery ? Wrapper("Recovery") : null,
    };

    public static object Wrapper(string type, int nonceLen = 12) => new
    {
        wrapperType = type,
        encryptedVaultKey = RandomNumberGenerator.GetBytes(32),
        nonce = RandomNumberGenerator.GetBytes(nonceLen),
        authTag = RandomNumberGenerator.GetBytes(16),
        keyVersion = 1,
    };

}
