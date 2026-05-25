using System.Security.Cryptography;
using System.Text;

public class DeviceFingerprintService
{
    public string Generate(HttpRequest request, string? clientEntropy)
    {
        var raw = string.Join("|",
            request.Headers.UserAgent.ToString(),
            request.Headers.AcceptLanguage.ToString(),
            clientEntropy ?? ""
        );

        using var sha = SHA256.Create();

        return Convert.ToHexString(
            sha.ComputeHash(Encoding.UTF8.GetBytes(raw))
        );
    }
}
