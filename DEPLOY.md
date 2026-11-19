# Deploying API Vault to Railway

Three services in one Railway project:

```
Browser ──HTTPS──► frontend (Caddy, public domain) ──/api/*──► api (private only) ──► Postgres
```

The browser only ever talks to the frontend's domain; Caddy forwards `/api/*` to the API over Railway's private
network. That keeps the HttpOnly refresh cookie and Google sign-in first-party, and the API needs no public domain.

## 1. Postgres

In your Railway project: **New → Database → PostgreSQL**. Nothing to configure.

## 2. API (this repo, `jandales/ApiVault`)

**New → GitHub Repo → jandales/ApiVault.** Railway picks up `railway.json` and builds the `Dockerfile`.
Rename the service to `api` (the frontend's variable below refers to it). **Do not generate a public domain.**

Variables (Service → Variables):

| Variable | Value |
|---|---|
| `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (reference: selects PostgreSQL automatically) |
| `PORT` | `8080` |
| `Jwt__Key` | a random secret, at least 32 characters (see below) |
| `Auth__FrontendUrl` | `https://<your-frontend>.up.railway.app` (no trailing slash) |
| `Auth__RequireConfirmedEmail` | `true` |
| `Google__ClientId` | your OAuth client ID |
| `Google__ClientSecret` | your OAuth client secret |
| `Email__Smtp__Host` | your SMTP host |
| `Email__Smtp__Port` | e.g. `587` or `2525` |
| `Email__Smtp__EnableSsl` | `true` |
| `Email__Smtp__Username` | SMTP username |
| `Email__Smtp__Password` | SMTP password |
| `Email__Smtp__From` | sender address |
| `Email__Smtp__FromName` | `API Vault` |

Generate the JWT key in PowerShell:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
```

On start the API applies migrations (`Database__MigrateOnStartup=true` is set in the Dockerfile) and Railway checks
`/health`, which also verifies the database connection. The deploy log prints the `ApiVault.Startup` lines
(database provider, Google enabled/disabled, email mode).

Note: Mailtrap's **sandbox** catches all mail instead of delivering it. For real users use a sending service
(Mailtrap Email Sending, SendGrid, Postmark, ...).

## 3. Frontend (`jandales/ApiVault-Frontend`)

**New → GitHub Repo → jandales/ApiVault-Frontend.** It also builds from its `Dockerfile`.
Then **Settings → Networking → Generate Domain**. Use that domain for `Auth__FrontendUrl` above.

| Variable | Value |
|---|---|
| `API_UPSTREAM` | `http://${{api.RAILWAY_PRIVATE_DOMAIN}}:8080` |

## 4. Google Cloud Console

In your OAuth client, add the production redirect URI:

```
https://<your-frontend>.up.railway.app/api/v1/auth/google/callback
```

## Notes

- **Client IPs / rate limiting:** the API trusts `X-Forwarded-For` only on Railway and walks back two hops
  (edge → Caddy → API). If you ever give the API its own public domain, set `Hosting__ForwardLimit=1`.
- **Data protection keys** (email-verification/reset tokens, Google sign-in cookies) are stored in the database, so
  links keep working across redeploys.
- **Local development** is unchanged: SQL Server via `ConnectionStrings:DefaultConnection`. To try Postgres locally
  set `Database__Provider=Postgres` and a Npgsql connection string.
- **New migrations** must be added for both providers:

  ```powershell
  dotnet ef migrations add <Name> -p ApiVault.Infrastructure -s ApiVault.API -o Data/Migrations
  $env:Database__Provider="Postgres"; $env:ConnectionStrings__DefaultConnection="Host=localhost;Database=apivault;Username=x;Password=x"
  dotnet ef migrations add <Name> -p ApiVault.Migrations.Postgres -s ApiVault.API -o Migrations
  ```
