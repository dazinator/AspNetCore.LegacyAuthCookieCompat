using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AspNetCore.LegacyAuthCookieCompat
{
    // From https://github.com/synercoder/FormsAuthentication/blob/master/src/Synercoding.FormsAuthentication/Encryption/AspNetCryptoServiceProvider.cs
    // From https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dataprotector?view=netframework-4.8
    static class KeyDerivator
    {
        public static readonly UTF8Encoding SecureUTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        public static byte[] DeriveKey(byte[] keyDerivationKey, CompatibilityMode compatibilityMode)
        {
            if (compatibilityMode == CompatibilityMode.Framework20SP2)
            {
                return keyDerivationKey;
            }

            using (HMACSHA512 hmac = new HMACSHA512(keyDerivationKey))
            {
                byte[] label, context;
                GetKeyDerivationParameters(out label, out context);

                byte[] derivedKey = DeriveKeyImpl(hmac, label, context, keyDerivationKey.Length * 8);
                return derivedKey;
            }
        }

        private static void GetKeyDerivationParameters(out byte[] label, out byte[] context)
        {
            label = SecureUTF8Encoding.GetBytes("FormsAuthentication.Ticket");
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream, SecureUTF8Encoding))
            {
                context = stream.ToArray();
            }
        }

        private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
        {
            checked
            {
                int labelLength = (label != null) ? label.Length : 0;
                int contextLength = (context != null) ? context.Length : 0;
                byte[] buffer = new byte[4 /* [i]_2 */ + labelLength /* label */ + 1 /* 0x00 */ + contextLength /* context */ + 4 /* [L]_2 */];

                if (labelLength != 0)
                {
                    Buffer.BlockCopy(label, 0, buffer, 4, labelLength); // the 4 accounts for the [i]_2 length
                }
                if (contextLength != 0)
                {
                    Buffer.BlockCopy(context, 0, buffer, 5 + labelLength, contextLength); // the '5 +' accounts for the [i]_2 length, the label, and the 0x00 byte
                }
                WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, buffer, 5 + labelLength + contextLength); // the '5 +' accounts for the [i]_2 length, the label, the 0x00 byte, and the context

                // Initialization

                int numBytesWritten = 0;
                int numBytesRemaining = keyLengthInBits / 8;
                byte[] output = new byte[numBytesRemaining];

                // Calculate each K_i value and copy the leftmost bits to the output buffer as appropriate.

                for (uint i = 1; numBytesRemaining > 0; i++)
                {
                    WriteUInt32ToByteArrayBigEndian(i, buffer, 0); // set the first 32 bits of the buffer to be the current iteration value
                    byte[] K_i = hmac.ComputeHash(buffer);

                    // copy the leftmost bits of K_i into the output buffer
                    int numBytesToCopy = Math.Min(numBytesRemaining, K_i.Length);
                    Buffer.BlockCopy(K_i, 0, output, numBytesWritten, numBytesToCopy);
                    numBytesWritten += numBytesToCopy;
                    numBytesRemaining -= numBytesToCopy;
                }

                // finished
                return output;
            }
        }

        private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value);
        }
    }
}
