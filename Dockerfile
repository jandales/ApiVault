# API Vault backend: ASP.NET Core 10 API. Railway (or any container host) builds this file.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first, in a cached layer, from the project files only.
COPY ApiVault.API/ApiVault.API.csproj ApiVault.API/
COPY ApiVault.Core/ApiVault.Core.csproj ApiVault.Core/
COPY ApiVault.BusinessLayer/ApiVault.BusinessLayer.csproj ApiVault.BusinessLayer/
COPY ApiVault.Infrastructure/ApiVault.Infrastructure.csproj ApiVault.Infrastructure/
COPY ApiVault.Migrations.Postgres/ApiVault.Migrations.Postgres.csproj ApiVault.Migrations.Postgres/
RUN dotnet restore ApiVault.API/ApiVault.API.csproj

COPY . .
RUN dotnet publish ApiVault.API/ApiVault.API.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Production defaults. Everything secret (Jwt__Key, DATABASE_URL, Google__*, Email__Smtp__*) comes from
# the platform's environment variables, never from this image.
ENV ASPNETCORE_ENVIRONMENT=Production \
    Database__MigrateOnStartup=true \
    DOTNET_RUNNING_IN_CONTAINER=true

# Railway sets PORT; 8080 is the default when running the image elsewhere.
ENV PORT=8080
EXPOSE 8080

# Non-root user that ships with the official .NET images.
USER $APP_UID
ENTRYPOINT ["dotnet", "ApiVault.API.dll"]
