using FortyOneForce.EntraSimulator.Configuration;
using FortyOneForce.EntraSimulator.Endpoints;
using FortyOneForce.EntraSimulator.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<EntraSimulatorOptions>(
    builder.Configuration.GetSection(EntraSimulatorOptions.SectionName));

builder.Services.AddSingleton<RsaKeyService>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<AuthorizationCodeStore>();
builder.Services.AddSingleton<RefreshTokenStore>();

var app = builder.Build();

app.MapOidcEndpoints();
app.MapAuthEndpoints();

app.Run();

// Partial class for test accessibility
public partial class Program { }
