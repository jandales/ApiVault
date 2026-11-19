using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using ApiVault.Core.DTOs;
using ApiVault.Infrastructure.Data;
using ApiVault.Tests.IntegrationTests;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace ApiVault.Tests.SecurityTests;

public class GoogleLoginTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _f;
    public GoogleLoginTests(ApiFactory f) => _f = f;

    private static ExternalIdentity Identity(string? email = null, bool verified = true, string? sub = null) =>
        new("Google", sub ?? Guid.NewGuid().ToString("N"), email ?? $"g-{Guid.NewGuid():N}@gmail.com", verified, "Test User");

    /// <summary>Runs start → (Google) → callback, returning the callback response.</summary>
    private async Task<HttpResponseMessage> SignInWithGoogleAsync(ExternalIdentity id, bool tamperState = false, bool dropCookie = false)
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var start = await http.GetAsync("/api/v1/auth/google/start");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var state = HttpUtility.ParseQueryString(start.Headers.Location!.Query)["state"]!;
        var flowCookie = start.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("av_google_flow=")).Split(';')[0];

        var code = Guid.NewGuid().ToString("N");
        _f.Google.Codes[code] = id;
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"/api/v1/auth/google/callback?code={code}&state={Uri.EscapeDataString(tamperState ? state + "x" : state)}");
        if (!dropCookie) req.Headers.Add("Cookie", flowCookie);
        return await http.SendAsync(req);
    }

    private static string Location(HttpResponseMessage res) => res.Headers.Location!.OriginalString;

    private static string? Fragment(HttpResponseMessage res, string key)
    {
        var loc = Location(res);
        var hash = loc.IndexOf('#');
        return hash < 0 ? null : HttpUtility.ParseQueryString(loc[(hash + 1)..])[key];
    }

    [Fact]
    public async Task Providers_endpoint_reports_google()
    {
        _f.EnsureDatabase();
        var p = await TestClient.NewHttp(_f).GetFromJsonAsync<JsonElement>("/api/v1/auth/providers");
        Assert.True(p.GetProperty("google").GetBoolean());
    }

    [Fact]
    public async Task Start_redirects_to_google_with_pkce_and_an_encrypted_flow_cookie()
    {
        _f.EnsureDatabase();
        var start = await TestClient.NewHttp(_f).GetAsync("/api/v1/auth/google/start");
        Assert.Equal(HttpStatusCode.Redirect, start.StatusCode);
        var location = start.Headers.Location!.ToString();
        Assert.StartsWith("https://accounts.google.com/", location);
        Assert.Contains("code_challenge_method=S256", location);

        var cookie = start.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("av_google_flow="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        var state = HttpUtility.ParseQueryString(start.Headers.Location!.Query)["state"]!;
        Assert.DoesNotContain(state, cookie); // the state is stored encrypted, not in clear
    }

    [Fact]
    public async Task Callback_with_wrong_state_or_missing_cookie_is_rejected()
    {
        Assert.Contains("status=error", Location(await SignInWithGoogleAsync(Identity(), tamperState: true)));
        Assert.Contains("status=error", Location(await SignInWithGoogleAsync(Identity(), dropCookie: true)));
    }

    [Fact]
    public async Task Unverified_google_email_is_refused_and_no_account_is_created()
    {
        var id = Identity(verified: false);
        var res = await SignInWithGoogleAsync(id);
        Assert.Contains("status=unverified", Location(res));
        Assert.False(res.Headers.TryGetValues("Set-Cookie", out var cookies) && cookies.Any(c => c.StartsWith("av_refresh=") && !c.Contains("expires=Thu, 01 Jan 1970")));
    }

    [Fact]
    public async Task New_google_user_sets_up_encryption_then_can_also_log_in_with_password()
    {
        var id = Identity();
        var res = await SignInWithGoogleAsync(id);
        Assert.Contains("status=setup", Location(res));
        var ticket = Fragment(res, "ticket");
        Assert.False(string.IsNullOrEmpty(ticket));
        Assert.Equal(id.Email, Fragment(res, "email"));
        Assert.DoesNotContain("ticket=", Location(res).Split('#')[0]); // never in the query string

        var http = TestClient.NewHttp(_f);
        var vaultId = Guid.NewGuid();
        var reg = await http.PostAsJsonAsync("/api/v1/auth/google/register",
            new { ticket, password = TestClient.Password, vault = TestClient.NewVaultRequest(vaultId) });
        Assert.Equal(HttpStatusCode.OK, reg.StatusCode);
        Assert.Contains(reg.Headers.GetValues("Set-Cookie"), c => c.StartsWith("av_refresh="));
        var body = await reg.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("user").GetProperty("emailConfirmed").GetBoolean()); // Google verified it

        // Same account works with email + password (derived auth key) too.
        var login = await http.PostAsJsonAsync("/api/v1/auth/login", new { email = id.Email, password = TestClient.Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        // The ticket cannot be replayed to create a second account.
        var again = await http.PostAsJsonAsync("/api/v1/auth/google/register",
            new { ticket, password = TestClient.Password, vault = TestClient.NewVaultRequest() });
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        // Next Google sign-in goes straight in.
        Assert.Contains("status=signed-in", Location(await SignInWithGoogleAsync(id)));
    }

    [Fact]
    public async Task Existing_account_is_linked_by_verified_email_and_keeps_its_vault()
    {
        var u = await TestClient.RegisterAndLoginAsync(_f);
        var res = await SignInWithGoogleAsync(Identity(email: u.Email));
        Assert.Contains("status=signed-in", Location(res));
        var refresh = res.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("av_refresh=")).Split(';')[0]["av_refresh=".Length..];

        // The issued session works and belongs to the existing user, whose single vault is unchanged.
        var refreshed = await u.RefreshAsync(refresh);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var vaults = await u.Http.GetFromJsonAsync<JsonElement>("/api/v1/vaults");
        Assert.Equal(1, vaults.GetProperty("totalCount").GetInt32());
        Assert.Equal(u.VaultId, vaults.GetProperty("items")[0].GetProperty("id").GetGuid());

        using var scope = _f.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.True(await db.UserLogins.AnyAsync(l => l.UserId == u.UserId && l.LoginProvider == "Google"));
    }

    [Fact]
    public async Task Tampered_or_missing_ticket_is_rejected()
    {
        _f.EnsureDatabase();
        var http = TestClient.NewHttp(_f);
        var res = await http.PostAsJsonAsync("/api/v1/auth/google/register",
            new { ticket = "not-a-real-ticket", password = TestClient.Password, vault = TestClient.NewVaultRequest() });
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Google_sign_in_does_not_return_any_key_material()
    {
        var id = Identity();
        var res = await SignInWithGoogleAsync(id);
        var http = TestClient.NewHttp(_f);
        var reg = await http.PostAsJsonAsync("/api/v1/auth/google/register",
            new { ticket = Fragment(res, "ticket"), password = TestClient.Password, vault = TestClient.NewVaultRequest() });
        var body = await reg.Content.ReadAsStringAsync();
        Assert.DoesNotContain("encryptedVaultKey", body);
        Assert.DoesNotContain("kdfSalt", body);
    }
}
