using Aspire.Hosting;
using FortyOneForce.EntraSimulator.Aspire;

var builder = DistributedApplication.CreateBuilder(args);

// Add the Entra Simulator project and configure it
var entra = builder.AddProject<Projects.FortyOneForce_EntraSimulator>("entra")
    .WithHttpEndpoint(port: 5010, name: "http")
    .AsEntraSimulator()
    .WithTenant("tenant1", tenant => tenant
        .WithAppRegistration(
            clientId: "22222222-2222-2222-2222-222222222222",
            clientSecret: "super-secret",
            redirectUris: "http://localhost:5001/signin-oidc")
        .WithUser(
            userPrincipalName: "testuser@contoso.com",
            password: "Password123!",
            displayName: "Test User"));

builder.Build().Run();
