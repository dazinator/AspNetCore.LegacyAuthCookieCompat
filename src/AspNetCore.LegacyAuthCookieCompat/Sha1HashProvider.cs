using System.Security.Cryptography;

namespace AspNetCore.LegacyAuthCookieCompat
{
    public class Sha1HashProvider : HashProvider
    {
        const int Sha1HashSize = 20;
        const int Sha1KeySize = 64;

        public Sha1HashProvider(byte[] validationKey)
            : base(validationKey, Sha1HashSize, Sha1KeySize)
        {
        }

        protected override HMAC CreateHasher(byte[] key) => new HMACSHA1(key);
    }
}
