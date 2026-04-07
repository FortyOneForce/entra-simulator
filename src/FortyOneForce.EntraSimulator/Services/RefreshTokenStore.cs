using System.Collections.Concurrent;

namespace FortyOneForce.EntraSimulator.Services;

public record RefreshTokenData(
    string TenantId,
    string ClientId,
    string UserId,
    string[] Scopes,
    DateTime ExpiresAt);

public class RefreshTokenStore
{
    private readonly ConcurrentDictionary<string, RefreshTokenData> _tokens = new();

    public void Store(string token, RefreshTokenData data)
        => _tokens[token] = data;

    public RefreshTokenData? ConsumeToken(string token)
    {
        if (_tokens.TryRemove(token, out var data))
        {
            if (data.ExpiresAt > DateTime.UtcNow)
                return data;
        }
        return null;
    }
}
