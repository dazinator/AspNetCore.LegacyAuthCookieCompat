using System.Security.Cryptography;

namespace AspNetCore.LegacyAuthCookieCompat
{
    internal class Sha384HashProvider : HashProvider
    {
        private const int Sha384HashSize = 48;
        private const int Sha384KeySize = 384;

        public Sha384HashProvider(byte[] validationKey)
            : base(validationKey, Sha384HashSize, Sha384KeySize)
        {
        }

        protected override HMAC CreateHasher(byte[] key) => new HMACSHA384(key);
    }
}