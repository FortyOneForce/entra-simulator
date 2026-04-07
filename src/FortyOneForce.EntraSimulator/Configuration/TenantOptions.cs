namespace FortyOneForce.EntraSimulator.Configuration;

public class TenantOptions
{
    public string TenantId { get; set; } = Guid.NewGuid().ToString();
    public string TenantName { get; set; } = "Default";
    public List<AppRegistrationOptions> AppRegistrations { get; set; } = new();
    public List<UserOptions> Users { get; set; } = new();
}
