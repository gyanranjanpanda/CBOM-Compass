using System;
using System.Security.Cryptography;

namespace Payments
{
    public class Signing
    {
        public RSA WeakKey()
        {
            return new RSACryptoServiceProvider(1024);
        }

        public RSA StrongKey()
        {
            var rsa = RSA.Create();
            rsa.KeySize = 3072;
            return rsa;
        }

        public byte[] Legacy(byte[] data)
        {
            using var md5 = MD5.Create();
            using var sha1 = new SHA1Managed();
            return md5.ComputeHash(data);
        }

        public SymmetricAlgorithm Bulk()
        {
            var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            return aes;
        }

        public SymmetricAlgorithm Older()
        {
            return new TripleDESCryptoServiceProvider();
        }

        public ECDsa Curve()
        {
            return ECDsa.Create(ECCurve.NamedCurves.nistP384);
        }

        public HMAC Mac()
        {
            return new HMACSHA256();
        }
    }
}
