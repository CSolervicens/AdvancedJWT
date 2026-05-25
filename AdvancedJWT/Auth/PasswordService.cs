using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

public class PasswordService
{
    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 1024 * 128
        };

        byte[] hash = argon2.GetBytes(32);

        return Convert.ToBase64String(salt) + "." +
               Convert.ToBase64String(hash);
    }

    public bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split('.');

        var salt = Convert.FromBase64String(parts[0]);
        var hash = Convert.FromBase64String(parts[1]);

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 1024 * 128
        };

        var computed = argon2.GetBytes(32);

        return CryptographicOperations.FixedTimeEquals(
            hash,
            computed
        );
    }
}
