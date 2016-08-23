using System;
using System.Runtime.InteropServices;

namespace AspNetCore.LegacyAuthCookieCompat
{
    public class Sha1HashProvider
    {

        public const int SHA1_HASH_SIZE = 20;
        public const int SHA1_KEY_SIZE = 64;

        private static int _HashSize;
        private static int _KeySize;

        private byte[] _validationKeyBlob;

        private byte[] _inner = null;
        private byte[] _outer = null;

        public Sha1HashProvider(string validationKey, int hashSize = SHA1_HASH_SIZE, int keySize = SHA1_KEY_SIZE)
        {
            _HashSize = hashSize;
            _KeySize = keySize;
            _validationKeyBlob = HexUtils.HexStringToByteArray(validationKey);
            SetInnerOuterKeys(_validationKeyBlob, ref _inner, ref _outer);
        }


        public byte[] GetHMACSHA1Hash(byte[] buf, byte[] modifier, int start, int length)
        {
            if (start < 0 || start > buf.Length)
                throw new ArgumentException("start");
            if (length < 0 || buf == null || (start + length) > buf.Length)
                throw new ArgumentException("length");
            byte[] hash = new byte[_HashSize];

            int hr = UnsafeNativeMethods.GetHMACSHA1Hash(buf, start, length,
                                                         modifier, (modifier == null) ? 0 : modifier.Length,
                                                         _inner, _inner.Length, _outer, _outer.Length,
                                                         hash, hash.Length);
            if (hr == 0)
                return hash;
            //_UseHMACSHA = false;
            return null;
        }

        public byte[] CheckHashAndRemove(byte[] bufHashed)
        {
            if (!CheckHash(bufHashed, bufHashed.Length - _HashSize))
                return null;

            byte[] buf2 = new byte[bufHashed.Length - _HashSize];
            Buffer.BlockCopy(bufHashed, 0, buf2, 0, buf2.Length);
            return buf2;
        }

        public bool CheckHash(byte[] decryptedCookie, int hashIndex)
        {
            // 2. SHA1 Hash is appended to the end.
            // Verify the hash matches by re-computing the hash for this message, and comparing.
            byte[] hashCheckBlob = GetHMACSHA1Hash(decryptedCookie, null, 0, hashIndex);
            if (hashCheckBlob == null)
            {
                throw new Exception();
            }

            //////////////////////////////////////////////////////////////////////
            // Step 2: Make sure the MAC has expected length
            if (hashCheckBlob == null || hashCheckBlob.Length != _HashSize)
                throw new Exception();


            // To prevent a timing attack, we should verify the entire hash instead of failing
            // early the first time we see a mismatched byte.            
            bool hashCheckFailed = false;
            for (int i = 0; i < _HashSize; i++)
            {
                if (hashCheckBlob[i] != decryptedCookie[hashIndex + i])
                {
                    hashCheckFailed = true;
                }
            }

            return !hashCheckFailed;
        }

        private static void SetInnerOuterKeys(byte[] validationKey, ref byte[] inner, ref byte[] outer)
        {
            byte[] key = null;
            if (validationKey.Length > _KeySize)
            {
                key = new byte[_HashSize];
                int hr = UnsafeNativeMethods.GetSHA1Hash(validationKey, validationKey.Length, key, key.Length);
                Marshal.ThrowExceptionForHR(hr);
            }

            if (inner == null)
                inner = new byte[_KeySize];
            if (outer == null)
                outer = new byte[_KeySize];

            int i;
            for (i = 0; i < _KeySize; i++)
            {
                inner[i] = 0x36;
                outer[i] = 0x5C;
            }
            for (i = 0; i < validationKey.Length; i++)
            {
                inner[i] ^= validationKey[i];
                outer[i] ^= validationKey[i];
            }
        }

        public int HashSize { get { return _HashSize; } }

        public byte[] GetIVHash(byte[] buf, int ivLength)
        {
            // return an IV that is computed as a hash of the buffer
            int bytesToWrite = ivLength;
            int bytesWritten = 0;
            byte[] iv = new byte[ivLength];

            // get SHA1 hash of the buffer and copy to the IV.
            // if hash length is less than IV length, re-hash the hash and
            // append until IV is full.
            byte[] hash = buf;
            while (bytesWritten < ivLength)
            {
                byte[] newHash = new byte[_HashSize];
                int hr = UnsafeNativeMethods.GetSHA1Hash(hash, hash.Length, newHash, newHash.Length);
                Marshal.ThrowExceptionForHR(hr);
                hash = newHash;

                int bytesToCopy = Math.Min(_HashSize, bytesToWrite);
                Buffer.BlockCopy(hash, 0, iv, bytesWritten, bytesToCopy);

                bytesWritten += bytesToCopy;
                bytesToWrite -= bytesToCopy;
            }
            return iv;
        }


    }
}
