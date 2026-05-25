using System.Security.Cryptography;
using System.Text;

public static class TokenGenerator
{
    public static string GenerateSecureToken()
    {
        return Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(64)
        );
    }

    public static string Sha256(string input)
    {
        using var sha = SHA256.Create();

        return Convert.ToHexString(
            sha.ComputeHash(
                Encoding.UTF8.GetBytes(input)
            )
        );
    }
}