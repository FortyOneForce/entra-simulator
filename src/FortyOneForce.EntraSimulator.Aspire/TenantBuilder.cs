using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace FortyOneForce.EntraSimulator.Aspire;

/// <summary>
/// Provides a fluent API for configuring a tenant within the Entra Simulator.
/// </summary>
public class TenantBuilder
{
    private readonly string _key;

    internal string TenantId { get; } = Guid.NewGuid().ToString();
    internal string TenantName { get; }
    internal List<AppRegistrationEntry> AppRegistrations { get; } = new();
    internal List<UserEntry> Users { get; } = new();

    internal TenantBuilder(string key)
    {
        _key = key;
        TenantName = key;
    }

    /// <summary>Adds an app registration to this tenant.</summary>
    public TenantBuilder WithAppRegistration(string clientId, string clientSecret, params string[] redirectUris)
    {
        AppRegistrations.Add(new AppRegistrationEntry(clientId, clientSecret, [.. redirectUris],
            ["openid", "profile", "email", "offline_access"]));
        return this;
    }

    /// <summary>Adds a user to this tenant.</summary>
    public TenantBuilder WithUser(
        string userPrincipalName,
        string password,
        string? displayName = null,
        string? objectId = null)
    {
        Users.Add(new UserEntry(
            objectId ?? Guid.NewGuid().ToString(),
            userPrincipalName,
            displayName ?? userPrincipalName,
            password));
        return this;
    }

    internal string Key => _key;
}

internal record AppRegistrationEntry(string ClientId, string ClientSecret, List<string> RedirectUris, List<string> Scopes);
internal record UserEntry(string ObjectId, string UserPrincipalName, string DisplayName, string Password);
