namespace FortyOneForce.EntraSimulator.Configuration;

public class AppRegistrationOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
}
