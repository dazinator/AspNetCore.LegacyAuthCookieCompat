using System;
using System.IO;
using System.Security.Cryptography;

namespace AspNetCore.LegacyAuthCookieCompat
{
    public class LegacyFormsAuthenticationTicketEncryptor
    {
        private const ShaVersion DefaultHashAlgorithm = ShaVersion.Sha1;
        private const CompatibilityMode DefaultCompatibilityMode = CompatibilityMode.Framework20SP2;

        private static RandomNumberGenerator _randomNumberGenerator;
        private static RandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (_randomNumberGenerator == null)
                {
                    _randomNumberGenerator = RandomNumberGenerator.Create();
                }
                return _randomNumberGenerator;
            }
        }

        private byte[] _DecryptionKeyBlob = null;
        private CompatibilityMode _CompatibilityMode;

        private HashProvider _hasher;

        public LegacyFormsAuthenticationTicketEncryptor(string decryptionKey, string validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
        {
            byte[] descriptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
            byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);

            Initialize(descriptionKeyBytes, validationKeyBytes, hashAlgorithm, compatibilityMode);
        }

        public LegacyFormsAuthenticationTicketEncryptor(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm = DefaultHashAlgorithm, CompatibilityMode compatibilityMode = DefaultCompatibilityMode)
        {
            Initialize(decryptionKey, validationKey, hashAlgorithm, compatibilityMode);
        }

        private void Initialize(byte[] decryptionKey, byte[] validationKey, ShaVersion hashAlgorithm, CompatibilityMode compatibilityMode)
        {
            _CompatibilityMode = compatibilityMode;
            _DecryptionKeyBlob = KeyDerivator.DeriveKey(decryptionKey, _CompatibilityMode);

            _hasher = HashProvider.Create(KeyDerivator.DeriveKey(validationKey, _CompatibilityMode), hashAlgorithm);
        }

        /// <summary>
        /// Decrypts the ticket
        /// </summary>
        /// <param name="cookieString"></param>
        /// <returns></returns>
        public FormsAuthenticationTicket DecryptCookie(string cookieString)
        {
            byte[] cookieBlob = null;
            // 1. Convert from hex to binary.
            if ((cookieString.Length % 2) == 0)
            { // Could be a hex string
                try
                {
                    cookieBlob = HexUtils.HexToBinary(cookieString);
                }
                catch { }
            }

            if (cookieBlob == null)
            {
                return null;
            }

            // decrypt
            byte[] decryptedCookie = Decrypt(cookieBlob, _hasher, true);
            int ticketLength = decryptedCookie.Length;

            if (_CompatibilityMode == CompatibilityMode.Framework20SP2)
            {
                ticketLength = decryptedCookie.Length - _hasher.HashSize;
                bool validHash = _hasher.CheckHash(decryptedCookie, ticketLength);

                if (!validHash)
                {
                    throw new Exception("Invalid Hash");
                }
            }

            return FormsAuthenticationTicketHelper.Deserialize(decryptedCookie, ticketLength);
        }

        private byte[] EncryptCookieData(byte[] cookieBlob, int length, HashProvider hasher = null)
        {

            using (var aesProvider = Aes.Create())
            {
                aesProvider.Key = _DecryptionKeyBlob;
                aesProvider.BlockSize = 128;
                aesProvider.GenerateIV();

                if (_CompatibilityMode == CompatibilityMode.Framework20SP2)
                {
                    aesProvider.IV = new byte[aesProvider.IV.Length];
                    aesProvider.Mode = CipherMode.CBC;
                }
                else if (hasher != null)
                {
                    aesProvider.IV = hasher.GetIVHash(cookieBlob, aesProvider.IV.Length);
                }

                var decryptor = aesProvider.CreateEncryptor();

                using (var ms = new MemoryStream())
                {
                    // first write the iv.
                    if (_CompatibilityMode != CompatibilityMode.Framework20SP2)
                    {
                        ms.Write(aesProvider.IV, 0, aesProvider.IV.Length);
                    }

                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        bool sign = false;
                        if (_CompatibilityMode == CompatibilityMode.Framework20SP2)
                        {
                            bool createIv = true;
                            bool useRandomIv = true;

                            if (createIv)
                            {
                                int ivLength = RoundupNumBitsToNumBytes(aesProvider.KeySize);
                                byte[] iv = null;

                                if (hasher != null)
                                {
                                    iv = hasher.GetIVHash(cookieBlob, ivLength);
                                }
                                else if (useRandomIv)
                                {
                                    iv = new byte[ivLength];
                                    RandomNumberGenerator.GetBytes(iv);
                                }

                                // first write the iv.
                                cs.Write(iv, 0, iv.Length);
                            }
                        }

                        // then write ticket data.
                        cs.Write(cookieBlob, 0, cookieBlob.Length);

                        cs.FlushFinalBlock();
                        byte[] paddedData = ms.ToArray();

                        if (_CompatibilityMode == CompatibilityMode.Framework20SP2 && sign)
                        {
                            throw new NotImplementedException();
                            // append signature to encrypted bytes.
                        }

                        return paddedData;

                    }

                }
            }
        }

        private byte[] Decrypt(byte[] cookieBlob, HashProvider hasher, bool isHashAppended)
        {
            if (hasher == null)
            {
                throw new ArgumentNullException("hasher");
            }

            if (isHashAppended)
            {
                // need to check the hash signature, and strip it off the end of the byte array.
                cookieBlob = hasher.CheckHashAndRemove(cookieBlob);
                if (cookieBlob == null)
                {
                    // signature verification failed
                    throw new CryptographicException("Signature verification failed");
                }
            }

            // Now decrypt the encrypted cookie data.
            using (var aesProvider = Aes.Create())
            {
                aesProvider.Key = _DecryptionKeyBlob;
                aesProvider.BlockSize = 128;
                if (_CompatibilityMode == CompatibilityMode.Framework20SP2)
                {
                    aesProvider.GenerateIV();
                    aesProvider.IV = new byte[aesProvider.IV.Length];
                    aesProvider.Mode = CipherMode.CBC;
                }
                else
                {
                    byte[] iv = new byte[aesProvider.IV.Length];
                    Buffer.BlockCopy(cookieBlob, 0, iv, 0, iv.Length);
                    aesProvider.IV = iv;
                }

                using (var ms = new MemoryStream())
                {
                    using (var decryptor = aesProvider.CreateDecryptor())
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            if (_CompatibilityMode == CompatibilityMode.Framework20SP2)
                            {
                                cs.Write(cookieBlob, 0, cookieBlob.Length);
                            }
                            else
                            {
                                cs.Write(cookieBlob, aesProvider.IV.Length, cookieBlob.Length - aesProvider.IV.Length);
                            }

                            cs.FlushFinalBlock();
                            byte[] paddedData = ms.ToArray();

                            if (_CompatibilityMode != CompatibilityMode.Framework20SP2)
                            {
                                return paddedData;
                            }

                            // The data contains some random bytes prepended at the start. Remove them.
                            int ivLength = RoundupNumBitsToNumBytes(aesProvider.KeySize);
                            int dataLength = paddedData.Length - ivLength;
                            if (dataLength < 0)
                            {
                                throw new Exception($"Unexpected salt length: {ivLength}. Total: {paddedData.Length}");
                            }

                            byte[] decryptedData = new byte[dataLength];
                            Buffer.BlockCopy(paddedData, ivLength, decryptedData, 0, dataLength);
                            return decryptedData;
                        }
                    }
                }
            }
        }

        internal static int RoundupNumBitsToNumBytes(int numBits)
        {
            if (numBits < 0)
                return 0;
            return (numBits / 8) + (((numBits & 7) != 0) ? 1 : 0);
        }

        /// <summary>
        /// Encrypts the ticket, and if a hasher is provided, will also include a signature in the encrypted data.
        /// </summary>
        /// <param name="ticket"></param>
        /// <param name="hasher">If hasher it not null, it will be used to generate hash which is used to sign the encrypted data by adding it to the end. If it is null, no signature will be added.</param>
        /// <param name="randomiseUsingHash">If true, the hash of the encrypted data will be prepended to the beginning, otherwise random bytes will be generated and prepended to the beggining.</param>
        /// <returns></returns>
        public string Encrypt(FormsAuthenticationTicket ticket, bool randomiseUsingHash = false)
        {
            // make ticked into binary blob.
            byte[] ticketBlob = FormsAuthenticationTicketHelper.Serialize(ticket);
            if (ticketBlob == null)
            {
                throw new Exception("Invalid ticket");
            }

            byte[] cookieBlob = ticketBlob;

            // Compute a hash and add to the blob.
            if (_CompatibilityMode == CompatibilityMode.Framework20SP2 && _hasher != null)
            {
                byte[] hashBlob = _hasher.GetHMACSHAHash(ticketBlob, null, 0, ticketBlob.Length);
                if (hashBlob == null)
                {
                    throw new Exception("Unable to get HMACSHAHash");
                }

                // create a new byte array big enough to store the ticket data, and the hash data which is appended to the end.
                cookieBlob = new byte[hashBlob.Length + ticketBlob.Length];
                Buffer.BlockCopy(ticketBlob, 0, cookieBlob, 0, ticketBlob.Length);
                Buffer.BlockCopy(hashBlob, 0, cookieBlob, ticketBlob.Length, hashBlob.Length);
            }

            // now encrypt the cookie data.
            byte[] encryptedCookieBlob = EncryptCookieData(cookieBlob, cookieBlob.Length, randomiseUsingHash ? _hasher : null);

            if (encryptedCookieBlob == null)
            {
                throw new Exception("Unable to encrypt cookie");
            }

            // sign the encrypted blob 
            if (_hasher != null)
            {
                byte[] hashBlob = _hasher.GetHMACSHAHash(encryptedCookieBlob, null, 0, encryptedCookieBlob.Length);
                if (hashBlob == null)
                {
                    throw new Exception("Unable to sign cookie");
                }

                // create a new byte array big enough to store the cookie data, and the hash which is appended to the end.
                cookieBlob = new byte[hashBlob.Length + encryptedCookieBlob.Length];
                Buffer.BlockCopy(encryptedCookieBlob, 0, cookieBlob, 0, encryptedCookieBlob.Length);
                Buffer.BlockCopy(hashBlob, 0, cookieBlob, encryptedCookieBlob.Length, hashBlob.Length);
            }

            // now convert the binary encrypted cookie data and return hex value.
            return HexUtils.BinaryToHex(cookieBlob);
        }

    }

}
