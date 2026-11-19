using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApiVault.Infrastructure.Data;
using ApiVault.Tests.IntegrationTests;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiVault.Tests.SecurityTests;

public class SecretSecurityTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _f;
    public SecretSecurityTests(ApiFactory f) => _f = f;

    private static object Payload(int size = 48) => new
    {
        encryptedPayload = RandomNumberGenerator.GetBytes(size),
        nonce = RandomNumberGenerator.GetBytes(12),
        authTag = RandomNumberGenerator.GetBytes(16),
        encryptionVersion = 1,
    };

    private static object NewSecret(Guid vaultId, string name = "Stripe live key", string type = "ApiKey",
        Guid[]? tagIds = null, DateTime? expiresAt = null, string? provider = "Stripe", byte[]? payload = null) => new
    {
        id = Guid.NewGuid(),
        vaultId,
        name,
        description = (string?)null,
        secretType = type,
        provider,
        environment = "Production",
        encryptedPayload = payload ?? RandomNumberGenerator.GetBytes(48),
        nonce = RandomNumberGenerator.GetBytes(12),
        authTag = RandomNumberGenerator.GetBytes(16),
        encryptionVersion = 1,
        expiresAt,
        tagIds = tagIds ?? [],
    };

    private static async Task<Guid> CreateSecretAsync(TestClient c, object body)
    {
        var res = await c.Http.PostAsJsonAsync("/api/v1/secrets", body);
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        return (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    private static async Task<Guid> CreateTagAsync(TestClient c, string name)
    {
        var res = await c.Http.PostAsJsonAsync("/api/v1/tags", new { name });
        Assert.Equal(HttpStatusCode.Created, res.StatusCode);
        return (await res.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Create_and_get_returns_ciphertext_and_metadata_only()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var payload = RandomNumberGenerator.GetBytes(64);
        var id = await CreateSecretAsync(u, NewSecret(vaultId, payload: payload));

        var s = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.Equal("Stripe live key", s.GetProperty("name").GetString());
        Assert.Equal(Convert.ToBase64String(payload), s.GetProperty("encryptedPayload").GetString());
        // No plaintext-looking fields exist on the record.
        foreach (var forbidden in new[] { "token", "password", "username", "tokenValue", "notes" })
            Assert.False(s.TryGetProperty(forbidden, out _), $"unexpected field {forbidden}");
    }

    [Fact]
    public async Task Database_stores_exactly_the_ciphertext_the_browser_sent()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        // A browser that misbehaved and sent plaintext would be visible here; a correct one sends ciphertext.
        var marker = Encoding.UTF8.GetBytes("sk_live_THIS_SHOULD_BE_CIPHERTEXT");
        var ciphertext = RandomNumberGenerator.GetBytes(64);
        var id = await CreateSecretAsync(u, NewSecret(vaultId, payload: ciphertext));

        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var row = await db.Secrets.AsNoTracking().SingleAsync(s => s.Id == id);
        Assert.Equal(ciphertext, row.EncryptedPayload);
        Assert.False(row.EncryptedPayload.AsSpan().IndexOf(marker) >= 0);
    }

    [Fact]
    public async Task User_cannot_read_modify_or_list_another_users_secrets()
    {
        var a = await TestClient.RegisterAndLoginAsync(_f);
        var b = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = a.VaultId;
        var id = await CreateSecretAsync(a, NewSecret(vaultId));

        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.GetAsync($"/api/v1/secrets/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.GetAsync($"/api/v1/secrets/{id}/versions")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PostAsJsonAsync($"/api/v1/secrets/{id}/versions", Payload())).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PostAsync($"/api/v1/secrets/{id}/archive", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PostAsync($"/api/v1/secrets/{id}/restore", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PutAsJsonAsync($"/api/v1/secrets/{id}",
            new { name = "x", secretType = "ApiKey" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.DeleteAsync($"/api/v1/secrets/{id}")).StatusCode);

        var list = await b.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets?vaultId={vaultId}");
        Assert.Equal(0, list.GetProperty("totalCount").GetInt32());

        // B cannot create a secret inside A's vault either.
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PostAsJsonAsync("/api/v1/secrets", NewSecret(vaultId))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await a.Http.GetAsync($"/api/v1/secrets/{id}")).StatusCode);
    }

    [Fact]
    public async Task Tag_owned_by_another_user_cannot_be_attached()
    {
        var a = await TestClient.RegisterAndLoginAsync(_f);
        var b = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = a.VaultId;
        var foreignTag = await CreateTagAsync(b, "b-tag");

        var res = await a.Http.PostAsJsonAsync("/api/v1/secrets", NewSecret(vaultId, tagIds: [foreignTag]));
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);

        var id = await CreateSecretAsync(a, NewSecret(vaultId));
        var upd = await a.Http.PutAsJsonAsync($"/api/v1/secrets/{id}", new { name = "x", secretType = "ApiKey", tagIds = new[] { foreignTag } });
        Assert.Equal(HttpStatusCode.BadRequest, upd.StatusCode);
    }

    [Fact]
    public async Task Payload_update_keeps_previous_ciphertext_as_a_version()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var original = RandomNumberGenerator.GetBytes(48);
        var id = await CreateSecretAsync(u, NewSecret(vaultId, payload: original));

        // Metadata-only edit: no version.
        var meta = await u.Http.PutAsJsonAsync($"/api/v1/secrets/{id}", new { name = "Renamed", secretType = "ApiKey", provider = "Stripe" });
        Assert.Equal(HttpStatusCode.OK, meta.StatusCode);
        Assert.Equal(0, (await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}/versions")).GetArrayLength());

        // Payload edit: previous payload preserved.
        var next = RandomNumberGenerator.GetBytes(48);
        var upd = await u.Http.PutAsJsonAsync($"/api/v1/secrets/{id}", new
        {
            name = "Renamed", secretType = "ApiKey",
            encryptedPayload = next, nonce = RandomNumberGenerator.GetBytes(12), authTag = RandomNumberGenerator.GetBytes(16), encryptionVersion = 1,
        });
        Assert.Equal(HttpStatusCode.OK, upd.StatusCode);

        // Payload-only rotation via the versions endpoint.
        Assert.Equal(HttpStatusCode.OK, (await u.Http.PostAsJsonAsync($"/api/v1/secrets/{id}/versions", Payload())).StatusCode);

        var versions = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}/versions");
        Assert.Equal(2, versions.GetArrayLength());
        var stored = versions.EnumerateArray().Select(v => v.GetProperty("encryptedPayload").GetString()).ToList();
        Assert.Contains(Convert.ToBase64String(original), stored);
        Assert.Contains(Convert.ToBase64String(next), stored);
    }

    [Fact]
    public async Task Archive_hides_from_default_list_and_restore_brings_back()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var id = await CreateSecretAsync(u, NewSecret(vaultId));

        Assert.Equal(HttpStatusCode.OK, (await u.Http.PostAsync($"/api/v1/secrets/{id}/archive", null)).StatusCode);
        Assert.Equal(0, (await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets?vaultId={vaultId}")).GetProperty("totalCount").GetInt32());
        Assert.Equal(1, (await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets?vaultId={vaultId}&archived=true")).GetProperty("totalCount").GetInt32());

        Assert.Equal(HttpStatusCode.OK, (await u.Http.PostAsync($"/api/v1/secrets/{id}/restore", null)).StatusCode);
        Assert.Equal(1, (await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets?vaultId={vaultId}")).GetProperty("totalCount").GetInt32());
    }

    [Fact]
    public async Task Delete_is_permanent_and_removes_versions()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var id = await CreateSecretAsync(u, NewSecret(vaultId));
        await u.Http.PostAsJsonAsync($"/api/v1/secrets/{id}/versions", Payload());

        Assert.Equal(HttpStatusCode.NoContent, (await u.Http.DeleteAsync($"/api/v1/secrets/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await u.Http.GetAsync($"/api/v1/secrets/{id}")).StatusCode);
        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.False(await db.SecretVersions.AnyAsync(v => v.SecretId == id));
    }

    [Fact]
    public async Task List_filters_by_search_type_tag_and_expiry()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var prod = await CreateTagAsync(u, "prod");
        await CreateSecretAsync(u, NewSecret(vaultId, "Stripe key", "ApiKey", [prod], DateTime.UtcNow.AddDays(3)));
        await CreateSecretAsync(u, NewSecret(vaultId, "GitHub token", "ApiKey", provider: "GitHub"));
        await CreateSecretAsync(u, NewSecret(vaultId, "DB admin", "Password", provider: null));

        async Task<int> Count(string qs) =>
            (await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets?vaultId={vaultId}&{qs}")).GetProperty("totalCount").GetInt32();

        Assert.Equal(3, await Count(""));
        Assert.Equal(2, await Count("secretType=ApiKey"));
        Assert.Equal(1, await Count("search=GitHub"));
        Assert.Equal(1, await Count($"tagId={prod}"));
        Assert.Equal(1, await Count("expiringWithinDays=30"));
    }

    [Theory]
    [InlineData("ApiKey", 8, 16, 48)]
    [InlineData("ApiKey", 12, 12, 48)]
    [InlineData("ApiKey", 12, 16, 0)]
    [InlineData("Unknown", 12, 16, 48)]
    public async Task Malformed_secret_is_rejected(string type, int nonceLen, int tagLen, int payloadLen)
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var body = new
        {
            id = Guid.NewGuid(), vaultId, name = "x", secretType = type,
            encryptedPayload = RandomNumberGenerator.GetBytes(payloadLen),
            nonce = RandomNumberGenerator.GetBytes(nonceLen), authTag = RandomNumberGenerator.GetBytes(tagLen), encryptionVersion = 1,
        };
        Assert.Equal(HttpStatusCode.BadRequest, (await u.Http.PostAsJsonAsync("/api/v1/secrets", body)).StatusCode);
    }

    [Fact]
    public async Task Tags_are_unique_per_user_and_isolated_between_users()
    {
        var a = await TestClient.RegisterAndLoginAsync(_f);
        var b = await TestClient.RegisterAndLoginAsync(_f);
        var tag = await CreateTagAsync(a, "shared-name");
        Assert.Equal(HttpStatusCode.Conflict, (await a.Http.PostAsJsonAsync("/api/v1/tags", new { name = "shared-name" })).StatusCode);
        await CreateTagAsync(b, "shared-name"); // same name, different user: fine

        Assert.Equal(1, (await b.Http.GetFromJsonAsync<JsonElement>("/api/v1/tags")).GetArrayLength());
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.PutAsJsonAsync($"/api/v1/tags/{tag}", new { name = "pwned" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.Http.DeleteAsync($"/api/v1/tags/{tag}")).StatusCode);
    }

    [Fact]
    public async Task Deleting_a_tag_detaches_it_from_secrets()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var vaultId = u.VaultId;
        var tag = await CreateTagAsync(u, "temp");
        var id = await CreateSecretAsync(u, NewSecret(vaultId, tagIds: [tag]));

        Assert.Equal(HttpStatusCode.NoContent, (await u.Http.DeleteAsync($"/api/v1/tags/{tag}")).StatusCode);
        var s = await u.Http.GetFromJsonAsync<JsonElement>($"/api/v1/secrets/{id}");
        Assert.Equal(0, s.GetProperty("tags").GetArrayLength());
    }

}
