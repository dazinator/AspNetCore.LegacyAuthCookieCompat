using System.Security.Cryptography;

namespace AspNetCore.LegacyAuthCookieCompat
{
    internal class Sha384HashProvider : HashProvider
    {
        private const int Sha1HashSize = 48;
        private const int Sha1KeySize = 384;

        public Sha384HashProvider(byte[] validationKey)
            : base(validationKey, Sha1HashSize, Sha1KeySize)
        {
        }

        protected override HMAC CreateHasher(byte[] key) => new HMACSHA384(key);
    }
}