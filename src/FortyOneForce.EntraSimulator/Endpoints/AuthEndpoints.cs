using System.Net;
using System.Text;
using System.Web;
using Microsoft.Extensions.Options;
using FortyOneForce.EntraSimulator.Configuration;
using FortyOneForce.EntraSimulator.Services;

namespace FortyOneForce.EntraSimulator.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        // Authorization endpoint - GET shows login UI
        app.MapGet("/{tenantId}/oauth2/v2.0/authorize", HandleAuthorizeGet);

        // Authorization endpoint - POST processes login form
        app.MapPost("/{tenantId}/oauth2/v2.0/authorize", HandleAuthorizePost);

        // Token endpoint
        app.MapPost("/{tenantId}/oauth2/v2.0/token", HandleToken);
    }

    private static IResult HandleAuthorizeGet(
        string tenantId,
        HttpRequest request,
        IOptions<EntraSimulatorOptions> options)
    {
        var query = request.Query;
        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var nonce = query["nonce"].ToString();
        var responseType = query["response_type"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        var tenant = OidcEndpoints.ResolveTenant(tenantId, options.Value);
        var tenantName = tenant?.TenantName ?? tenantId;
        var appReg = tenant?.AppRegistrations.FirstOrDefault(a =>
            string.Equals(a.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
        var appName = appReg?.ClientId ?? clientId;
        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var html = BuildLoginPage(tenantId, tenantName, appName, requestedScopes, clientId,
            redirectUri, scope, state, nonce, responseType, codeChallenge, codeChallengeMethod);

        return Results.Content(html, "text/html");
    }

    private static async Task<IResult> HandleAuthorizePost(
        string tenantId,
        HttpRequest request,
        IOptions<EntraSimulatorOptions> options,
        AuthorizationCodeStore codeStore)
    {
        var form = await request.ReadFormAsync();
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        var clientId = form["client_id"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var scope = form["scope"].ToString();
        var state = form["state"].ToString();
        var nonce = form["nonce"].ToString();
        var codeChallenge = form["code_challenge"].ToString();
        var codeChallengeMethod = form["code_challenge_method"].ToString();

        var tenant = OidcEndpoints.ResolveTenant(tenantId, options.Value);
        if (tenant == null)
            return Results.BadRequest("Tenant not found.");

        // Validate app registration
        var appReg = tenant.AppRegistrations.FirstOrDefault(a =>
            string.Equals(a.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
        if (appReg == null)
            return Results.BadRequest("Client not found.");

        // Validate redirect URI
        if (!appReg.RedirectUris.Contains(redirectUri))
            return Results.BadRequest("Invalid redirect_uri.");

        // Validate user credentials
        var user = tenant.Users.FirstOrDefault(u =>
            string.Equals(u.UserPrincipalName, username, StringComparison.OrdinalIgnoreCase) &&
            u.Password == password);

        if (user == null)
        {
            // Re-show login page with error
            var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var html = BuildLoginPage(tenantId, tenant.TenantName, appReg.ClientId, requestedScopes,
                clientId, redirectUri, scope, state, nonce, "code", codeChallenge, codeChallengeMethod,
                error: "Invalid username or password.");
            return Results.Content(html, "text/html");
        }

        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var codeData = new AuthorizationCodeData(
            tenant.TenantId,
            clientId,
            user.ObjectId,
            redirectUri,
            scopes,
            string.IsNullOrEmpty(nonce) ? null : nonce,
            string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
            DateTime.UtcNow.AddMinutes(10));

        var code = codeStore.GenerateCode(codeData);

        var callbackUrl = BuildCallbackUrl(redirectUri, code, state);
        return Results.Redirect(callbackUrl);
    }

    private static async Task<IResult> HandleToken(
        string tenantId,
        HttpRequest request,
        IOptions<EntraSimulatorOptions> options,
        AuthorizationCodeStore codeStore,
        RefreshTokenStore refreshTokenStore,
        TokenService tokenService,
        RsaKeyService keyService)
    {
        var form = await request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();

        var baseUrl = OidcEndpoints.GetBaseUrl(request);
        var tenant = OidcEndpoints.ResolveTenant(tenantId, options.Value);
        if (tenant == null)
            return TokenError("invalid_request", "Tenant not found.");

        var issuer = $"{baseUrl}/{tenant.TenantId}/v2.0";

        return grantType switch
        {
            "authorization_code" => await HandleAuthCodeExchange(form, request, tenant, issuer, codeStore, refreshTokenStore, tokenService, options.Value),
            "client_credentials" => HandleClientCredentials(form, request, tenant, issuer, tokenService),
            "refresh_token" => await HandleRefreshToken(form, tenant, issuer, refreshTokenStore, tokenService, options.Value),
            _ => TokenError("unsupported_grant_type", $"Grant type '{grantType}' is not supported.")
        };
    }

    private static async Task<IResult> HandleAuthCodeExchange(
        IFormCollection form,
        HttpRequest request,
        TenantOptions tenant,
        string issuer,
        AuthorizationCodeStore codeStore,
        RefreshTokenStore refreshTokenStore,
        TokenService tokenService,
        EntraSimulatorOptions options)
    {
        var code = form["code"].ToString();
        var clientId = form["client_id"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var clientSecret = form["client_secret"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        // Support Basic auth (client_secret_basic)
        var (basicClientId, basicClientSecret) = ExtractBasicAuth(request);
        if (string.IsNullOrEmpty(clientId)) clientId = basicClientId;
        if (string.IsNullOrEmpty(clientSecret)) clientSecret = basicClientSecret;

        var codeData = codeStore.ConsumeCode(code);
        if (codeData == null)
            return TokenError("invalid_grant", "Authorization code is invalid or expired.");

        if (!string.Equals(codeData.ClientId, clientId, StringComparison.OrdinalIgnoreCase))
            return TokenError("invalid_grant", "client_id mismatch.");

        if (!string.Equals(codeData.RedirectUri, redirectUri, StringComparison.Ordinal))
            return TokenError("invalid_grant", "redirect_uri mismatch.");

        // PKCE verification
        if (!string.IsNullOrEmpty(codeData.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
                return TokenError("invalid_grant", "code_verifier is required.");

            if (!AuthorizationCodeStore.VerifyCodeVerifier(codeData.CodeChallenge, codeData.CodeChallengeMethod ?? "plain", codeVerifier))
                return TokenError("invalid_grant", "code_verifier is invalid.");
        }
        else if (!string.IsNullOrEmpty(clientSecret))
        {
            // Validate client secret
            var appReg = tenant.AppRegistrations.FirstOrDefault(a =>
                string.Equals(a.ClientId, clientId, StringComparison.OrdinalIgnoreCase));
            if (appReg == null || appReg.ClientSecret != clientSecret)
                return TokenError("invalid_client", "Invalid client credentials.");
        }

        var user = tenant.Users.FirstOrDefault(u => u.ObjectId == codeData.UserId);
        if (user == null)
            return TokenError("invalid_grant", "User not found.");

        var accessToken = tokenService.GenerateAccessToken(issuer, clientId, user, tenant, codeData.Scopes);
        var idToken = tokenService.GenerateIdToken(issuer, clientId, user, tenant, codeData.Nonce);
        var refreshToken = tokenService.GenerateRefreshToken();

        refreshTokenStore.Store(refreshToken, new RefreshTokenData(
            tenant.TenantId, clientId, user.ObjectId, codeData.Scopes,
            DateTime.UtcNow.AddDays(90)));

        return Results.Json(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600,
            id_token = idToken,
            refresh_token = refreshToken,
            scope = string.Join(" ", codeData.Scopes),
        });
    }

    private static IResult HandleClientCredentials(
        IFormCollection form,
        HttpRequest request,
        TenantOptions tenant,
        string issuer,
        TokenService tokenService)
    {
        var clientId = form["client_id"].ToString();
        var clientSecret = form["client_secret"].ToString();
        var scope = form["scope"].ToString();

        // Support Basic auth (client_secret_basic)
        var (basicClientId, basicClientSecret) = ExtractBasicAuth(request);
        if (string.IsNullOrEmpty(clientId)) clientId = basicClientId;
        if (string.IsNullOrEmpty(clientSecret)) clientSecret = basicClientSecret;

        var appReg = tenant.AppRegistrations.FirstOrDefault(a =>
            string.Equals(a.ClientId, clientId, StringComparison.OrdinalIgnoreCase));

        if (appReg == null || appReg.ClientSecret != clientSecret)
            return TokenError("invalid_client", "Invalid client credentials.");

        var accessToken = tokenService.GenerateClientCredentialsToken(issuer, clientId, clientId, tenant.TenantId);

        return Results.Json(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600,
            scope = scope,
        });
    }

    private static async Task<IResult> HandleRefreshToken(
        IFormCollection form,
        TenantOptions tenant,
        string issuer,
        RefreshTokenStore refreshTokenStore,
        TokenService tokenService,
        EntraSimulatorOptions options)
    {
        var refreshToken = form["refresh_token"].ToString();
        var clientId = form["client_id"].ToString();

        var tokenData = refreshTokenStore.ConsumeToken(refreshToken);
        if (tokenData == null)
            return TokenError("invalid_grant", "Refresh token is invalid or expired.");

        if (!string.Equals(tokenData.ClientId, clientId, StringComparison.OrdinalIgnoreCase))
            return TokenError("invalid_grant", "client_id mismatch.");

        var user = tenant.Users.FirstOrDefault(u => u.ObjectId == tokenData.UserId);
        if (user == null)
            return TokenError("invalid_grant", "User not found.");

        var accessToken = tokenService.GenerateAccessToken(issuer, clientId, user, tenant, tokenData.Scopes);
        var idToken = tokenService.GenerateIdToken(issuer, clientId, user, tenant, null);
        var newRefreshToken = tokenService.GenerateRefreshToken();

        refreshTokenStore.Store(newRefreshToken, tokenData with
        {
            ExpiresAt = DateTime.UtcNow.AddDays(90)
        });

        return Results.Json(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 3600,
            id_token = idToken,
            refresh_token = newRefreshToken,
            scope = string.Join(" ", tokenData.Scopes),
        });
    }

    private static IResult TokenError(string error, string description)
        => Results.Json(new { error, error_description = description }, statusCode: 400);

    private static string BuildCallbackUrl(string redirectUri, string code, string state)
    {
        var sb = new StringBuilder(redirectUri);
        sb.Append(redirectUri.Contains('?') ? '&' : '?');
        sb.Append("code=");
        sb.Append(WebUtility.UrlEncode(code));
        if (!string.IsNullOrEmpty(state))
        {
            sb.Append("&state=");
            sb.Append(WebUtility.UrlEncode(state));
        }
        return sb.ToString();
    }

    private static (string clientId, string clientSecret) ExtractBasicAuth(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.ToString();
        if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (string.Empty, string.Empty);

        try
        {
            var encoded = authHeader["Basic ".Length..].Trim();
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var separator = decoded.IndexOf(':');
            if (separator < 0)
                return (string.Empty, string.Empty);

            var clientId = decoded[..separator];
            var clientSecret = decoded[(separator + 1)..];
            return (clientId, clientSecret);
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    private static string BuildLoginPage(
        string tenantId,
        string tenantName,
        string appName,
        string[] scopes,
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string responseType,
        string codeChallenge,
        string codeChallengeMethod,
        string? error = null)
    {
        var scopeList = string.Join(", ", scopes.Where(s => s != "openid" && s != "offline_access"));
        var errorHtml = error != null
            ? $"<div class=\"error\">{WebUtility.HtmlEncode(error)}</div>"
            : string.Empty;

        var scopesHtml = scopeList.Length > 0
            ? $"<div class=\"scopes\"><strong>{WebUtility.HtmlEncode(appName)}</strong> is requesting access to: {WebUtility.HtmlEncode(scopeList)}</div>"
            : string.Empty;

        return "<!DOCTYPE html>" +
            "<html lang=\"en\"><head>" +
            "<meta charset=\"UTF-8\">" +
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" +
            $"<title>Sign in to {WebUtility.HtmlEncode(tenantName)}</title>" +
            "<style>" +
            "body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f3f3;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}" +
            ".card{background:white;border-radius:8px;padding:40px;width:360px;box-shadow:0 2px 12px rgba(0,0,0,0.1)}" +
            "h1{font-size:24px;margin:0 0 8px;color:#1a1a1a}" +
            ".subtitle{color:#666;font-size:14px;margin-bottom:24px}" +
            ".scopes{background:#f8f8f8;border-radius:4px;padding:12px;font-size:13px;color:#444;margin-bottom:20px}" +
            "label{display:block;font-size:14px;font-weight:600;margin-bottom:4px;color:#1a1a1a}" +
            "input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ccc;border-radius:4px;font-size:14px;margin-bottom:16px}" +
            "button{width:100%;padding:12px;background:#0078d4;color:white;border:none;border-radius:4px;font-size:16px;cursor:pointer}" +
            "button:hover{background:#005a9e}" +
            ".error{background:#fde7e7;color:#c00;border-radius:4px;padding:10px 12px;font-size:14px;margin-bottom:16px}" +
            ".simulator-badge{text-align:center;font-size:11px;color:#999;margin-top:20px}" +
            "</style></head><body>" +
            "<div class=\"card\">" +
            "<h1>Sign in</h1>" +
            $"<div class=\"subtitle\">{WebUtility.HtmlEncode(tenantName)} \u00b7 Entra ID Simulator</div>" +
            scopesHtml +
            errorHtml +
            $"<form method=\"post\" action=\"/{WebUtility.UrlEncode(tenantId)}/oauth2/v2.0/authorize\">" +
            $"<input type=\"hidden\" name=\"client_id\" value=\"{WebUtility.HtmlEncode(clientId)}\" />" +
            $"<input type=\"hidden\" name=\"redirect_uri\" value=\"{WebUtility.HtmlEncode(redirectUri)}\" />" +
            $"<input type=\"hidden\" name=\"scope\" value=\"{WebUtility.HtmlEncode(scope)}\" />" +
            $"<input type=\"hidden\" name=\"state\" value=\"{WebUtility.HtmlEncode(state)}\" />" +
            $"<input type=\"hidden\" name=\"nonce\" value=\"{WebUtility.HtmlEncode(nonce)}\" />" +
            $"<input type=\"hidden\" name=\"response_type\" value=\"{WebUtility.HtmlEncode(responseType)}\" />" +
            $"<input type=\"hidden\" name=\"code_challenge\" value=\"{WebUtility.HtmlEncode(codeChallenge)}\" />" +
            $"<input type=\"hidden\" name=\"code_challenge_method\" value=\"{WebUtility.HtmlEncode(codeChallengeMethod)}\" />" +
            "<label for=\"username\">Email or username</label>" +
            "<input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" required />" +
            "<label for=\"password\">Password</label>" +
            "<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required />" +
            "<button type=\"submit\">Sign in</button>" +
            "</form>" +
            "<div class=\"simulator-badge\">Entra ID Simulator \u2014 Not for production use</div>" +
            "</div></body></html>";
    }
}
