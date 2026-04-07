using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using FortyOneForce.EntraSimulator.Configuration;
using FortyOneForce.EntraSimulator.Services;

namespace FortyOneForce.EntraSimulator.Endpoints;

public static class OidcEndpoints
{
    public static void MapOidcEndpoints(this WebApplication app)
    {
        // Default well-known redirects to common tenant
        app.MapGet("/.well-known/openid-configuration", (HttpContext ctx) =>
        {
            ctx.Response.Redirect("/common/.well-known/openid-configuration");
            return Task.CompletedTask;
        });

        // OIDC discovery document (Azure v2.0 style paths)
        app.MapGet("/{tenantId}/.well-known/openid-configuration", HandleDiscovery);
        app.MapGet("/{tenantId}/v2.0/.well-known/openid-configuration", HandleDiscovery);

        // JWKS endpoint
        app.MapGet("/{tenantId}/discovery/v2.0/keys", HandleJwks);

        // UserInfo endpoint
        app.MapGet("/{tenantId}/oidc/userinfo", HandleUserInfo);
        app.MapPost("/{tenantId}/oidc/userinfo", HandleUserInfo);
    }

    private static IResult HandleDiscovery(string tenantId, HttpRequest request, IOptions<EntraSimulatorOptions> options)
    {
        var baseUrl = GetBaseUrl(request);
        var tenant = ResolveTenant(tenantId, options.Value);
        var effectiveTenantId = tenant?.TenantId ?? tenantId;

        var doc = new OidcDiscoveryDocument
        {
            Issuer = $"{baseUrl}/{effectiveTenantId}/v2.0",
            AuthorizationEndpoint = $"{baseUrl}/{effectiveTenantId}/oauth2/v2.0/authorize",
            TokenEndpoint = $"{baseUrl}/{effectiveTenantId}/oauth2/v2.0/token",
            JwksUri = $"{baseUrl}/{effectiveTenantId}/discovery/v2.0/keys",
            UserinfoEndpoint = $"{baseUrl}/{effectiveTenantId}/oidc/userinfo",
            ResponseTypesSupported = ["code", "id_token", "token", "code id_token"],
            SubjectTypesSupported = ["pairwise"],
            IdTokenSigningAlgValuesSupported = ["RS256"],
            TokenEndpointAuthMethodsSupported = ["client_secret_post", "client_secret_basic"],
            ScopesSupported = ["openid", "profile", "email", "offline_access"],
            ClaimsSupported = ["sub", "iss", "aud", "exp", "iat", "name", "email", "oid", "tid", "preferred_username", "given_name", "family_name"],
            GrantTypesSupported = ["authorization_code", "client_credentials", "refresh_token"],
            CodeChallengeMethodsSupported = ["plain", "S256"],
        };

        return Results.Json(doc, JsonSerializerOptions.Default);
    }

    private static IResult HandleJwks(string tenantId, RsaKeyService keyService)
    {
        var jwk = keyService.GetPublicJsonWebKey();
        var response = new
        {
            keys = new[]
            {
                new
                {
                    kty = jwk.Kty,
                    use = jwk.Use,
                    kid = jwk.Kid,
                    alg = jwk.Alg,
                    n = jwk.N,
                    e = jwk.E
                }
            }
        };
        return Results.Json(response);
    }

    private static IResult HandleUserInfo(string tenantId, HttpRequest request,
        IOptions<EntraSimulatorOptions> options, RsaKeyService keyService)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Results.Unauthorized();

        var token = authHeader["Bearer ".Length..].Trim();

        try
        {
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            var sub = jwt.Subject;
            var tid = jwt.Claims.FirstOrDefault(c => c.Type == "tid")?.Value;

            var tenant = FindTenantById(tid ?? tenantId, options.Value);
            if (tenant == null)
                return Results.NotFound();

            var user = tenant.Users.FirstOrDefault(u => u.ObjectId == sub);
            if (user == null)
                return Results.NotFound();

            var userInfo = new Dictionary<string, object>
            {
                ["sub"] = user.ObjectId,
                ["name"] = user.DisplayName,
                ["email"] = user.UserPrincipalName,
                ["preferred_username"] = user.UserPrincipalName,
                ["oid"] = user.ObjectId,
                ["tid"] = tenant.TenantId,
            };

            foreach (var claim in user.Claims)
                userInfo[claim.Key] = claim.Value;

            return Results.Json(userInfo);
        }
        catch
        {
            return Results.Unauthorized();
        }
    }

    internal static string GetBaseUrl(HttpRequest request)
    {
        var scheme = request.Scheme;
        var host = request.Host.ToUriComponent();
        return $"{scheme}://{host}";
    }

    internal static TenantOptions? ResolveTenant(string tenantId, EntraSimulatorOptions options)
    {
        // Try by key name
        if (options.Tenants.TryGetValue(tenantId, out var byKey))
            return byKey;

        // Try by TenantId value
        return options.Tenants.Values.FirstOrDefault(t =>
            string.Equals(t.TenantId, tenantId, StringComparison.OrdinalIgnoreCase));
    }

    internal static TenantOptions? FindTenantById(string tenantId, EntraSimulatorOptions options)
        => options.Tenants.Values.FirstOrDefault(t =>
            string.Equals(t.TenantId, tenantId, StringComparison.OrdinalIgnoreCase));
}

public class OidcDiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = string.Empty;

    [JsonPropertyName("authorization_endpoint")]
    public string AuthorizationEndpoint { get; set; } = string.Empty;

    [JsonPropertyName("token_endpoint")]
    public string TokenEndpoint { get; set; } = string.Empty;

    [JsonPropertyName("jwks_uri")]
    public string JwksUri { get; set; } = string.Empty;

    [JsonPropertyName("userinfo_endpoint")]
    public string UserinfoEndpoint { get; set; } = string.Empty;

    [JsonPropertyName("response_types_supported")]
    public string[] ResponseTypesSupported { get; set; } = [];

    [JsonPropertyName("subject_types_supported")]
    public string[] SubjectTypesSupported { get; set; } = [];

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public string[] IdTokenSigningAlgValuesSupported { get; set; } = [];

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public string[] TokenEndpointAuthMethodsSupported { get; set; } = [];

    [JsonPropertyName("scopes_supported")]
    public string[] ScopesSupported { get; set; } = [];

    [JsonPropertyName("claims_supported")]
    public string[] ClaimsSupported { get; set; } = [];

    [JsonPropertyName("grant_types_supported")]
    public string[] GrantTypesSupported { get; set; } = [];

    [JsonPropertyName("code_challenge_methods_supported")]
    public string[] CodeChallengeMethodsSupported { get; set; } = [];
}
