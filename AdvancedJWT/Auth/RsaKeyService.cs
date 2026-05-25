using System.Security.Cryptography;

public class RsaKeyService
{
    public RSA GetPrivateKey()
    {
        var rsa = RSA.Create();
        var privateKeyPem = File.ReadAllText("Keys/private.pem");
        rsa.ImportFromPem(privateKeyPem);
        return rsa;
    }

    public RSA GetPublicKey()
    {
        var rsa = RSA.Create();
        var publicKeyPem = File.ReadAllText("Keys/public.pem");
        rsa.ImportFromPem(publicKeyPem);
        return rsa;
    }
}