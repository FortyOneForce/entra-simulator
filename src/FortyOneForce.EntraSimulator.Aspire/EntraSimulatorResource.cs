using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;

namespace FortyOneForce.EntraSimulator.Aspire;

/// <summary>
/// Represents an Entra Simulator resource in an Aspire distributed application.
/// </summary>
public class EntraSimulatorResource : ContainerResource, IResourceWithServiceDiscovery
{
    internal const string HttpEndpointName = "http";
    internal const int DefaultPort = 5010;

    public EntraSimulatorResource(string name) : base(name)
    {
    }
}
