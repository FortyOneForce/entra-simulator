namespace FortyOneForce.EntraSimulator.Configuration;

public class EntraSimulatorOptions
{
    public const string SectionName = "EntraSimulator";
    public Dictionary<string, TenantOptions> Tenants { get; set; } = new();
    public string DefaultTenantId { get; set; } = "common";
}
