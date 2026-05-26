using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;


public class JwtService
{
    private readonly IConfiguration _config;
    private readonly RSA _privateKey;

    public JwtService(IConfiguration config, RsaKeyService rsaKeyService)
    {
        _config = config;
        _privateKey = rsaKeyService.GetPrivateKey();
    }

    public (string token, string jti) GenerateAccessToken(User user)
    {
        var jti = Guid.NewGuid().ToString();

        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.Jti, jti),
        new Claim(ClaimTypes.Role, user.Role)
    };

        var credentials = new SigningCredentials(
            new RsaSecurityKey(_privateKey),
            SecurityAlgorithms.RsaSha256
        );

        double AccessTokenMinutes = double.Parse(_config["Jwt:AccessTokenMinutes"]);
        
        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(AccessTokenMinutes),
            signingCredentials: credentials
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenString = tokenHandler.WriteToken(token);

        return (
            tokenString,
            jti
        );
    }
}