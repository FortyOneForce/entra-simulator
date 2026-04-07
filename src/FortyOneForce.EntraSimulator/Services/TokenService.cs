using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using FortyOneForce.EntraSimulator.Configuration;

namespace FortyOneForce.EntraSimulator.Services;

public class TokenService
{
    private readonly RsaKeyService _keyService;

    public TokenService(RsaKeyService keyService)
    {
        _keyService = keyService;
    }

    public string GenerateAccessToken(string issuer, string audience, UserOptions user, TenantOptions tenant, string[] scopes)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.ObjectId),
            new("oid", user.ObjectId),
            new("tid", tenant.TenantId),
            new(JwtRegisteredClaimNames.Name, user.DisplayName),
            new(JwtRegisteredClaimNames.Email, user.UserPrincipalName),
            new("preferred_username", user.UserPrincipalName),
            new("scp", string.Join(" ", scopes)),
        };

        foreach (var claim in user.Claims)
            claims.Add(new Claim(claim.Key, claim.Value));

        return CreateToken(issuer, audience, claims, TimeSpan.FromHours(1));
    }

    public string GenerateIdToken(string issuer, string audience, UserOptions user, TenantOptions tenant, string? nonce)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.ObjectId),
            new("oid", user.ObjectId),
            new("tid", tenant.TenantId),
            new(JwtRegisteredClaimNames.Name, user.DisplayName),
            new(JwtRegisteredClaimNames.Email, user.UserPrincipalName),
            new("preferred_username", user.UserPrincipalName),
        };

        if (nonce != null)
            claims.Add(new Claim("nonce", nonce));

        foreach (var claim in user.Claims)
            claims.Add(new Claim(claim.Key, claim.Value));

        return CreateToken(issuer, audience, claims, TimeSpan.FromHours(1));
    }

    public string GenerateClientCredentialsToken(string issuer, string audience, string clientId, string tenantId)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new("oid", clientId),
            new("tid", tenantId),
            new("appid", clientId),
        };

        return CreateToken(issuer, audience, claims, TimeSpan.FromHours(1));
    }

    public string GenerateRefreshToken()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private string CreateToken(string issuer, string audience, List<Claim> claims, TimeSpan expiry)
    {
        var now = DateTime.UtcNow;
        var signingCredentials = new SigningCredentials(_keyService.GetSecurityKey(), SecurityAlgorithms.RsaSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: now,
            expires: now.Add(expiry),
            signingCredentials: signingCredentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
