using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace FortyOneForce.EntraSimulator.Services;

public record AuthorizationCodeData(
    string TenantId,
    string ClientId,
    string UserId,
    string RedirectUri,
    string[] Scopes,
    string? Nonce,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    DateTime ExpiresAt);

public class AuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCodeData> _codes = new();

    public string GenerateCode(AuthorizationCodeData data)
    {
        var code = Guid.NewGuid().ToString("N");
        _codes[code] = data;
        return code;
    }

    public AuthorizationCodeData? ConsumeCode(string code)
    {
        if (_codes.TryRemove(code, out var data))
        {
            if (data.ExpiresAt > DateTime.UtcNow)
                return data;
        }
        return null;
    }

    public static bool VerifyCodeVerifier(string codeChallenge, string codeChallengeMethod, string codeVerifier)
    {
        if (string.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            var computed = Base64UrlEncode(bytes);
            return computed == codeChallenge;
        }
        // plain
        return codeVerifier == codeChallenge;
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
