using System;
using System.IO;
using System.Security.Cryptography;
using System.Web.Security;

namespace AspNetCore.LegacyAuthCookieCompat
{
    public class LegacyFormsAuthenticationTicketEncryptor
    {
        private string _DecryptionKeyText = string.Empty;

        private static RNGCryptoServiceProvider _randomNumberGenerator;
        private static RNGCryptoServiceProvider RandomNumberGenerator
        {
            get
            {
                if (_randomNumberGenerator == null)
                {
                    _randomNumberGenerator = new RNGCryptoServiceProvider();
                }
                return _randomNumberGenerator;
            }
        }

        private byte[] _DecryptionKeyBlob = null;

        public LegacyFormsAuthenticationTicketEncryptor(string decryptionKey)
        {
            _DecryptionKeyText = decryptionKey;
            _DecryptionKeyBlob = HexUtils.HexStringToByteArray(decryptionKey);
        }

        public FormsAuthenticationTicket DecryptCookie(string cookieString, Sha1HashProvider hasher)
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

            // hasher = new Sha1HashProvider(_ValidationKeyText);

            byte[] decryptedCookie = Decrypt(cookieBlob, hasher, true);
            int ticketLength = decryptedCookie.Length - hasher.HashSize;

            // bool validHash = hasher.CheckHash(decryptedCookie, ticketLength);

            var newTicket = FormsAuthenticationTicketHelper.Deserialize(decryptedCookie, ticketLength);
            // var ticket = FormsAuthenticationTicketHelper.DeserialiseLegacy(decryptedCookie, ticketLength);
            return newTicket;



        }

        private byte[] EncryptCookieData(byte[] cookieBlob, int length, Sha1HashProvider hasher = null)
        {

            using (var aesProvider = new AesCryptoServiceProvider())
            {
                aesProvider.Key = _DecryptionKeyBlob;
                aesProvider.BlockSize = 128;
                aesProvider.GenerateIV();
                aesProvider.IV = new byte[aesProvider.IV.Length];
                aesProvider.Mode = CipherMode.CBC;
                var decryptor = aesProvider.CreateEncryptor();

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {

                        bool createIv = true;
                        bool useRandomIv = true;
                        bool sign = false;

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

                        // then write ticket data.
                        cs.Write(cookieBlob, 0, cookieBlob.Length);

                        cs.FlushFinalBlock();
                        byte[] paddedData = ms.ToArray();

                        if (sign)
                        {
                            throw new NotImplementedException();
                            // append signature to encrypted bytes.
                        }

                        return paddedData;

                    }

                }
            }
        }

        private byte[] Decrypt(byte[] cookieBlob, Sha1HashProvider hasher, bool isHashAppended)
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
                    throw new Exception();
                }
            }

            // Now decrypt the encrypted cookie data.
            using (var aesProvider = new AesCryptoServiceProvider())
            {
                aesProvider.Key = _DecryptionKeyBlob;
                aesProvider.BlockSize = 128;
                aesProvider.GenerateIV();
                aesProvider.IV = new byte[aesProvider.IV.Length];
                aesProvider.Mode = CipherMode.CBC;

                using (var ms = new MemoryStream())
                {
                    using (var decryptor = aesProvider.CreateDecryptor())
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(cookieBlob, 0, cookieBlob.Length);
                            cs.FlushFinalBlock();
                            byte[] paddedData = ms.ToArray();

                            // The data contains some random bytes prepended at the start. Remove them.
                            int ivLength = RoundupNumBitsToNumBytes(aesProvider.KeySize);
                            int dataLength = paddedData.Length - ivLength;
                            if (dataLength < 0)
                            {
                                throw new Exception();
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
        public string Encrypt(FormsAuthenticationTicket ticket, Sha1HashProvider hasher, bool randomiseUsingHash = false)
        {
            // make ticked into binary blob.
            byte[] ticketBlob = FormsAuthenticationTicketHelper.Serialize(ticket);
            if (ticketBlob == null)
            {
                throw new Exception();
            }

            byte[] cookieBlob = ticketBlob;

            // Compute a hash and add to the blob.
            if (hasher != null)
            {
                byte[] hashBlob = hasher.GetHMACSHA1Hash(ticketBlob, null, 0, ticketBlob.Length);
                if (hashBlob == null)
                {
                    throw new Exception();
                }

                // create a new byte array big enough to store the ticket data, and the hash data which is appended to the end.
                cookieBlob = new byte[hashBlob.Length + ticketBlob.Length];
                Buffer.BlockCopy(ticketBlob, 0, cookieBlob, 0, ticketBlob.Length);
                Buffer.BlockCopy(hashBlob, 0, cookieBlob, ticketBlob.Length, hashBlob.Length);
            }

            // now encrypt the cookie data.

            byte[] encryptedCookieBlob = EncryptCookieData(cookieBlob, cookieBlob.Length, randomiseUsingHash ? hasher : null);
            // byte[] signedEncryptedCookieBlob;

            if (encryptedCookieBlob == null)
            {
                throw new Exception();
            }

            // sign the encrypted blob 
            if (hasher != null)
            {
                byte[] hashBlob = hasher.GetHMACSHA1Hash(encryptedCookieBlob, null, 0, encryptedCookieBlob.Length);
                if (hashBlob == null)
                {
                    throw new Exception();
                }

                // create a new byte array big enough to store the cookie data, and the hash which is appended to the end.
                cookieBlob = new byte[hashBlob.Length + encryptedCookieBlob.Length];
                Buffer.BlockCopy(encryptedCookieBlob, 0, cookieBlob, 0, encryptedCookieBlob.Length);
                Buffer.BlockCopy(hashBlob, 0, cookieBlob, encryptedCookieBlob.Length, hashBlob.Length);
            }

            // now convert the binary encrypted cookie data to a hex value.


            var cookieData = HexUtils.BinaryToHex(cookieBlob);
            return cookieData;
        }

    }

}
