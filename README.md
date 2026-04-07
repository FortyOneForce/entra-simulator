# entra-simulator

A lightweight simulator for **Azure Entra ID** (formerly Azure Active Directory) and App Registrations, providing token issuance, OIDC flows, and local development support with **.NET Aspire**.

## Features

- 🔐 **Token issuance** — RSA-signed JWT access tokens and ID tokens (RS256)
- 🌐 **OIDC flows** — Authorization code flow (with PKCE), client credentials, refresh token rotation
- 🔑 **JWKS endpoint** — Public key exposure for token validation
- 🧑‍💻 **Login UI** — Simple HTML sign-in page with configurable users
- ⚙️ **Multi-tenant** — Configure multiple tenants with independent app registrations and users
- 🚀 **.NET Aspire integration** — Fluent builder API for integrating with Aspire AppHosts
- 🔗 **Azure SDK compatible** — Sets `AZURE_AUTHORITY_HOST` for consuming services

## Endpoints

The simulator mirrors Azure Entra ID's endpoint structure:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | Redirects to default tenant discovery |
| `GET` | `/{tenantId}/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/{tenantId}/v2.0/.well-known/openid-configuration` | OIDC discovery (v2.0 alias) |
| `GET` | `/{tenantId}/discovery/v2.0/keys` | JSON Web Key Set (JWKS) |
| `GET` | `/{tenantId}/oauth2/v2.0/authorize` | Authorization endpoint (login UI) |
| `POST` | `/{tenantId}/oauth2/v2.0/authorize` | Process login form |
| `POST` | `/{tenantId}/oauth2/v2.0/token` | Token endpoint |
| `GET/POST` | `/{tenantId}/oidc/userinfo` | UserInfo endpoint |

## Solution Structure

```
EntraSimulator.slnx
src/
  FortyOneForce.EntraSimulator/           # Core ASP.NET Core 9 service
  FortyOneForce.EntraSimulator.Aspire/    # .NET Aspire integration library
  FortyOneForce.EntraSimulator.AppHost/   # Sample Aspire AppHost
tests/
  FortyOneForce.EntraSimulator.Tests/     # Integration tests (xUnit)
```

## Quick Start

### Running standalone

```bash
cd src/FortyOneForce.EntraSimulator
dotnet run
```

The simulator starts on `http://localhost:5010` by default with a pre-configured Contoso tenant.

### Configuration (`appsettings.json`)

```json
{
  "EntraSimulator": {
    "Tenants": {
      "contoso": {
        "TenantId": "11111111-1111-1111-1111-111111111111",
        "TenantName": "Contoso",
        "AppRegistrations": [
          {
            "ClientId": "22222222-2222-2222-2222-222222222222",
            "ClientSecret": "super-secret",
            "RedirectUris": ["https://localhost:5001/signin-oidc"],
            "Scopes": ["openid", "profile", "email", "User.Read"]
          }
        ],
        "Users": [
          {
            "ObjectId": "33333333-3333-3333-3333-333333333333",
            "UserPrincipalName": "testuser@contoso.com",
            "DisplayName": "Test User",
            "Password": "Password123!",
            "Claims": {
              "given_name": "Test",
              "family_name": "User"
            }
          }
        ]
      }
    }
  }
}
```

### .NET Aspire Integration

Add the `FortyOneForce.EntraSimulator.Aspire` package to your AppHost and use the fluent builder:

```csharp
// In your Aspire AppHost Program.cs
var entra = builder.AddProject<Projects.FortyOneForce_EntraSimulator>("entra")
    .AsEntraSimulator()
    .WithTenant("contoso", t => t
        .WithTenantId("11111111-1111-1111-1111-111111111111")
        .WithTenantName("Contoso")
        .WithAppRegistration(
            clientId: "22222222-2222-2222-2222-222222222222",
            clientSecret: "super-secret",
            redirectUri: "https://localhost:5001/signin-oidc")
        .WithUser(
            upn: "testuser@contoso.com",
            password: "Password123!",
            displayName: "Test User"));

// Reference from consuming services — sets AZURE_AUTHORITY_HOST automatically
builder.AddProject<Projects.MyWebApp>("webapp")
    .WithReference(entra);
```

### Consuming in an ASP.NET Core App

Configure your app to use the simulator as its authority:

```csharp
// The AZURE_AUTHORITY_HOST env var is set automatically by Aspire when using WithReference(entra)
// Or configure manually for standalone use:
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "http://localhost:5010/11111111-1111-1111-1111-111111111111/v2.0";
        options.Audience = "22222222-2222-2222-2222-222222222222";
        options.RequireHttpsMetadata = false; // for local dev only
    });
```

## Supported OAuth 2.0 / OIDC Flows

| Flow | Grant Type |
|------|-----------|
| Authorization Code + PKCE | `authorization_code` with `code_challenge` / `code_verifier` |
| Authorization Code (secret) | `authorization_code` with `client_secret` |
| Client Credentials | `client_credentials` |
| Refresh Token | `refresh_token` |

## Building & Testing

```bash
# Build the solution
dotnet build EntraSimulator.slnx

# Run tests
dotnet test EntraSimulator.slnx
```

## ⚠️ Not for Production

This simulator is intended for **local development and testing only**. It does not implement production-grade security and must never be used to protect real resources.
