using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace FortyOneForce.EntraSimulator.Aspire;

/// <summary>
/// Builder for configuring the Entra Simulator resource before it is added to the application.
/// </summary>
public class EntraSimulatorBuilder
{
    private readonly IResourceBuilder<ProjectResource> _projectBuilder;

    internal EntraSimulatorBuilder(IResourceBuilder<ProjectResource> projectBuilder)
    {
        _projectBuilder = projectBuilder;
    }

    /// <summary>Adds or configures a tenant in the simulator.</summary>
    public EntraSimulatorBuilder WithTenant(string tenantKey, Action<TenantBuilder> configure)
    {
        var tb = new TenantBuilder(tenantKey);
        configure(tb);
        ApplyTenantConfig(tenantKey, tb);
        return this;
    }

    /// <summary>Sets the port the simulator listens on.</summary>
    public EntraSimulatorBuilder WithPort(int port)
    {
        _projectBuilder.WithHttpEndpoint(port: port, name: "http");
        return this;
    }

    private void ApplyTenantConfig(string tenantKey, TenantBuilder tb)
    {
        _projectBuilder.WithEnvironment($"EntraSimulator__Tenants__{tenantKey}__TenantId", tb.TenantId);
        _projectBuilder.WithEnvironment($"EntraSimulator__Tenants__{tenantKey}__TenantName", tb.TenantName);

        for (var i = 0; i < tb.AppRegistrations.Count; i++)
        {
            var app = tb.AppRegistrations[i];
            var prefix = $"EntraSimulator__Tenants__{tenantKey}__AppRegistrations__{i}";
            _projectBuilder.WithEnvironment($"{prefix}__ClientId", app.ClientId);
            _projectBuilder.WithEnvironment($"{prefix}__ClientSecret", app.ClientSecret);

            for (var j = 0; j < app.RedirectUris.Count; j++)
                _projectBuilder.WithEnvironment($"{prefix}__RedirectUris__{j}", app.RedirectUris[j]);

            for (var j = 0; j < app.Scopes.Count; j++)
                _projectBuilder.WithEnvironment($"{prefix}__Scopes__{j}", app.Scopes[j]);
        }

        for (var i = 0; i < tb.Users.Count; i++)
        {
            var user = tb.Users[i];
            var prefix = $"EntraSimulator__Tenants__{tenantKey}__Users__{i}";
            _projectBuilder.WithEnvironment($"{prefix}__ObjectId", user.ObjectId);
            _projectBuilder.WithEnvironment($"{prefix}__UserPrincipalName", user.UserPrincipalName);
            _projectBuilder.WithEnvironment($"{prefix}__DisplayName", user.DisplayName);
            _projectBuilder.WithEnvironment($"{prefix}__Password", user.Password);
        }
    }

    internal IResourceBuilder<ProjectResource> ProjectBuilder => _projectBuilder;
}
