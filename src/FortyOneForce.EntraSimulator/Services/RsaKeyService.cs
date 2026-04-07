using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace FortyOneForce.EntraSimulator.Services;

public class RsaKeyService
{
    private const int KeyIdLength = 8;
    private const int RsaKeySize = 2048;

    private readonly RSA _rsa;
    private readonly RsaSecurityKey _securityKey;
    private readonly string _keyId;

    public RsaKeyService()
    {
        _rsa = RSA.Create(RsaKeySize);
        _keyId = Guid.NewGuid().ToString("N")[..KeyIdLength];
        _securityKey = new RsaSecurityKey(_rsa) { KeyId = _keyId };
    }

    public RsaSecurityKey GetSecurityKey() => _securityKey;

    public string GetKeyId() => _keyId;

    public JsonWebKey GetPublicJsonWebKey()
    {
        var parameters = _rsa.ExportParameters(false);
        return new JsonWebKey
        {
            Kty = "RSA",
            Use = "sig",
            Kid = _keyId,
            Alg = "RS256",
            N = Base64UrlEncoder.Encode(parameters.Modulus!),
            E = Base64UrlEncoder.Encode(parameters.Exponent!)
        };
    }
}
