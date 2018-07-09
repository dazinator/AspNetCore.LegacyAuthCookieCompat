using System.Security.Cryptography;

namespace AspNetCore.LegacyAuthCookieCompat
{
    class Sha256HashProvider : HashProvider
    {
        const int Sha1HashSize = 32;
        const int Sha1KeySize = 256;

        public Sha256HashProvider(byte[] validationKey)
            : base(validationKey, Sha1HashSize, Sha1KeySize)
        {
        }

        protected override HMAC CreateHasher(byte[] key) => new HMACSHA256(key);
    }
}
