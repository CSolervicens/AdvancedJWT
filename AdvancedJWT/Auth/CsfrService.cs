using System.Security.Cryptography;

public class CsrfService
{
    public string Generate()
    {
        return Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(32)
        );
    }
}
