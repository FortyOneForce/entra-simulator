using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace FortyOneForce.EntraSimulator.Aspire;

/// <summary>
/// Extension methods for adding the Entra ID Simulator to an Aspire distributed application.
/// </summary>
public static class EntraSimulatorExtensions
{
    /// <summary>
    /// Wraps an existing Entra Simulator project resource with the fluent configuration builder.
    /// </summary>
    /// <param name="projectBuilder">The project resource builder returned by AddProject&lt;T&gt;.</param>
    /// <returns>An <see cref="EntraSimulatorBuilder"/> for further configuration.</returns>
    public static EntraSimulatorBuilder AsEntraSimulator(
        this IResourceBuilder<ProjectResource> projectBuilder)
        => new EntraSimulatorBuilder(projectBuilder);

    /// <summary>
    /// Configures the consuming resource to use the Entra Simulator by setting
    /// the AZURE_AUTHORITY_HOST environment variable.
    /// </summary>
    /// <param name="builder">The resource builder for the consuming project.</param>
    /// <param name="simulatorBuilder">The Entra Simulator builder.</param>
    /// <returns>The original resource builder for chaining.</returns>
    public static IResourceBuilder<TDestination> WithReference<TDestination>(
        this IResourceBuilder<TDestination> builder,
        EntraSimulatorBuilder simulatorBuilder)
        where TDestination : IResourceWithEnvironment
    {
        builder.WithEnvironment(ctx =>
        {
            var endpoint = simulatorBuilder.ProjectBuilder.Resource
                    .GetEndpoints()
                    .OrderByDescending(e => e.EndpointName == "https")
                    .FirstOrDefault(e => e.EndpointName == "http" || e.EndpointName == "https");

            if (endpoint != null)
                ctx.EnvironmentVariables["AZURE_AUTHORITY_HOST"] = endpoint.Url;
        });

        return builder;
    }
}
