using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using FortyOneForce.EntraSimulator.Services;

namespace FortyOneForce.EntraSimulator.Tests;

/// <summary>
/// Integration tests for the Entra ID Simulator using WebApplicationFactory.
/// </summary>
public class EntraSimulatorIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private const string TenantId = "11111111-1111-1111-1111-111111111111";
    private const string ClientId = "22222222-2222-2222-2222-222222222222";
    private const string ClientSecret = "super-secret";

    public EntraSimulatorIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    private HttpClient CreateClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
    });

    [Fact]
    public async Task OidcDiscovery_ReturnsTenantDocument()
    {
        var client = CreateClient();
        var response = await client.GetAsync($"/{TenantId}/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);

        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("issuer", out var issuer));
        Assert.Contains(TenantId, issuer.GetString()!);
        Assert.True(root.TryGetProperty("authorization_endpoint", out _));
        Assert.True(root.TryGetProperty("token_endpoint", out _));
        Assert.True(root.TryGetProperty("jwks_uri", out _));
    }

    [Fact]
    public async Task OidcDiscovery_AlternatePath_ReturnsTenantDocument()
    {
        var client = CreateClient();
        var response = await client.GetAsync($"/{TenantId}/v2.0/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.True(doc.RootElement.TryGetProperty("issuer", out _));
    }

    [Fact]
    public async Task Jwks_ReturnsValidRsaPublicKey()
    {
        var client = CreateClient();
        var response = await client.GetAsync($"/{TenantId}/discovery/v2.0/keys");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);

        var root = doc.RootElement;
        Assert.True(root.TryGetProperty("keys", out var keys));
        Assert.True(keys.GetArrayLength() > 0);

        var key = keys[0];
        Assert.True(key.TryGetProperty("kty", out var kty));
        Assert.Equal("RSA", kty.GetString());
        Assert.True(key.TryGetProperty("n", out _));
        Assert.True(key.TryGetProperty("e", out _));
        Assert.True(key.TryGetProperty("kid", out _));
        Assert.True(key.TryGetProperty("alg", out var alg));
        Assert.Equal("RS256", alg.GetString());
    }

    [Fact]
    public async Task AuthorizeEndpoint_Get_ReturnsLoginPage()
    {
        var client = CreateClient();
        var url = $"/{TenantId}/oauth2/v2.0/authorize"
            + $"?client_id={ClientId}"
            + $"&redirect_uri=https://localhost:5001/signin-oidc"
            + $"&response_type=code"
            + $"&scope=openid profile email"
            + $"&state=test-state";

        var response = await client.GetAsync(url);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("<form", html);
        Assert.Contains("username", html);
        Assert.Contains("password", html);
    }

    [Fact]
    public async Task AuthorizationCodeFlow_FullRoundTrip()
    {
        var client = CreateClient();

        // Step 1: POST to authorize with valid credentials
        var formData = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
            ["scope"] = "openid profile email",
            ["state"] = "my-state",
            ["nonce"] = "my-nonce",
            ["response_type"] = "code",
            ["username"] = "testuser@contoso.com",
            ["password"] = "Password123!",
        });

        var authorizeResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/authorize", formData);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location!;
        Assert.NotNull(location);

        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        var code = query["code"];
        var state = query["state"];

        Assert.NotNull(code);
        Assert.NotEmpty(code);
        Assert.Equal("my-state", state);

        // Step 2: Exchange code for tokens
        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
        });

        var tokenResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenDoc = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(tokenDoc);

        var root = tokenDoc.RootElement;
        Assert.True(root.TryGetProperty("access_token", out var accessToken));
        Assert.True(root.TryGetProperty("id_token", out var idToken));
        Assert.True(root.TryGetProperty("refresh_token", out var refreshToken));
        Assert.True(root.TryGetProperty("token_type", out var tokenType));
        Assert.Equal("Bearer", tokenType.GetString());

        // Step 3: Validate the access token using JWKS
        await ValidateTokenWithJwks(client, accessToken.GetString()!);
    }

    [Fact]
    public async Task ClientCredentialsFlow_ReturnsAccessToken()
    {
        var client = CreateClient();

        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
            ["scope"] = $"api://{ClientId}/.default",
        });

        var tokenResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var doc = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);

        Assert.True(doc.RootElement.TryGetProperty("access_token", out var accessToken));
        Assert.NotEmpty(accessToken.GetString()!);

        await ValidateTokenWithJwks(client, accessToken.GetString()!);
    }

    [Fact]
    public async Task RefreshTokenFlow_ReturnsNewTokens()
    {
        var client = CreateClient();

        // First get tokens via authorization code flow
        var formData = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
            ["scope"] = "openid profile email offline_access",
            ["state"] = "state",
            ["nonce"] = "nonce",
            ["response_type"] = "code",
            ["username"] = "testuser@contoso.com",
            ["password"] = "Password123!",
        });

        var authorizeResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/authorize", formData);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var query = System.Web.HttpUtility.ParseQueryString(authorizeResponse.Headers.Location!.Query);
        var code = query["code"]!;

        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
        });

        var tokenResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", tokenForm);
        var tokenDoc = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>();
        var refreshToken = tokenDoc!.RootElement.GetProperty("refresh_token").GetString()!;

        // Now use refresh token
        var refreshForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = ClientId,
            ["refresh_token"] = refreshToken,
        });

        var refreshResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", refreshForm);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var refreshDoc = await refreshResponse.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(refreshDoc);
        Assert.True(refreshDoc.RootElement.TryGetProperty("access_token", out _));
        Assert.True(refreshDoc.RootElement.TryGetProperty("refresh_token", out _));
    }

    [Fact]
    public async Task AuthorizationCodeFlow_InvalidPassword_ReturnsLoginPageWithError()
    {
        var client = CreateClient();

        var formData = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
            ["scope"] = "openid",
            ["state"] = "state",
            ["response_type"] = "code",
            ["username"] = "testuser@contoso.com",
            ["password"] = "WrongPassword!",
        });

        var response = await client.PostAsync($"/{TenantId}/oauth2/v2.0/authorize", formData);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var html = await response.Content.ReadAsStringAsync();
        Assert.Contains("Invalid username or password", html);
    }

    [Fact]
    public async Task TokenEndpoint_InvalidCode_ReturnsBadRequest()
    {
        var client = CreateClient();

        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "invalid-code",
            ["client_id"] = ClientId,
            ["client_secret"] = ClientSecret,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
        });

        var response = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", tokenForm);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var doc = await response.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(doc);
        Assert.True(doc.RootElement.TryGetProperty("error", out var error));
        Assert.Equal("invalid_grant", error.GetString());
    }

    [Fact]
    public async Task PkceFlow_FullRoundTrip()
    {
        var client = CreateClient();

        // Generate PKCE values
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        // Step 1: Authorize with PKCE
        var formData = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
            ["scope"] = "openid profile",
            ["state"] = "pkce-state",
            ["nonce"] = "pkce-nonce",
            ["response_type"] = "code",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["username"] = "testuser@contoso.com",
            ["password"] = "Password123!",
        });

        var authorizeResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/authorize", formData);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var query = System.Web.HttpUtility.ParseQueryString(authorizeResponse.Headers.Location!.Query);
        var code = query["code"]!;

        // Step 2: Exchange code with code_verifier
        var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["client_id"] = ClientId,
            ["redirect_uri"] = "https://localhost:5001/signin-oidc",
            ["code_verifier"] = codeVerifier,
        });

        var tokenResponse = await client.PostAsync($"/{TenantId}/oauth2/v2.0/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenDoc = await tokenResponse.Content.ReadFromJsonAsync<JsonDocument>();
        Assert.NotNull(tokenDoc);
        Assert.True(tokenDoc.RootElement.TryGetProperty("access_token", out _));
    }

    private async Task ValidateTokenWithJwks(HttpClient client, string token)
    {
        // Fetch JWKS
        var jwksResponse = await client.GetAsync($"/{TenantId}/discovery/v2.0/keys");
        var jwksDoc = await jwksResponse.Content.ReadFromJsonAsync<JsonDocument>();
        var keyElement = jwksDoc!.RootElement.GetProperty("keys")[0];

        var jwk = new JsonWebKey
        {
            Kty = keyElement.GetProperty("kty").GetString(),
            Use = keyElement.GetProperty("use").GetString(),
            Kid = keyElement.GetProperty("kid").GetString(),
            Alg = keyElement.GetProperty("alg").GetString(),
            N = keyElement.GetProperty("n").GetString(),
            E = keyElement.GetProperty("e").GetString(),
        };

        var handler = new JwtSecurityTokenHandler();
        var discoveryResponse = await client.GetAsync($"/{TenantId}/.well-known/openid-configuration");
        var discoveryDoc = await discoveryResponse.Content.ReadFromJsonAsync<JsonDocument>();
        var issuer = discoveryDoc!.RootElement.GetProperty("issuer").GetString()!;

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKey = jwk,
            ClockSkew = TimeSpan.Zero,
        };

        var principal = handler.ValidateToken(token, validationParameters, out var validatedToken);
        Assert.NotNull(principal);
        Assert.NotNull(validatedToken);
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.ASCII.GetBytes(codeVerifier));
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
