namespace FortyOneForce.EntraSimulator.Configuration;

public class UserOptions
{
    public string ObjectId { get; set; } = Guid.NewGuid().ToString();
    public string UserPrincipalName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public Dictionary<string, string> Claims { get; set; } = new();
}
