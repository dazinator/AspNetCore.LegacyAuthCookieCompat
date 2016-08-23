using System;

namespace AspNetCore.LegacyAuthCookieCompat
{
    public static class HexUtils
    {
        static byte[] s_ahexval;

        static internal byte[] HexStringToByteArray(String str)
        {
            if (((uint)str.Length & 0x1) == 0x1) // must be 2 nibbles per byte
            {
                return null;
            }
            byte[] ahexval = s_ahexval; // initialize a table for faster lookups
            if (ahexval == null)
            {
                ahexval = new byte['f' + 1];
                for (int i = ahexval.Length; --i >= 0;)
                {
                    if ('0' <= i && i <= '9')
                    {
                        ahexval[i] = (byte)(i - '0');
                    }
                    else if ('a' <= i && i <= 'f')
                    {
                        ahexval[i] = (byte)(i - 'a' + 10);
                    }
                    else if ('A' <= i && i <= 'F')
                    {
                        ahexval[i] = (byte)(i - 'A' + 10);
                    }
                }

                s_ahexval = ahexval;
            }

            byte[] result = new byte[str.Length / 2];
            int istr = 0, ir = 0;
            int n = result.Length;
            while (--n >= 0)
            {
                int c1, c2;
                try
                {
                    c1 = ahexval[str[istr++]];
                }
                catch (ArgumentNullException)
                {
                    c1 = 0;
                    return null;// Inavlid char
                }
                catch (ArgumentException)
                {
                    c1 = 0;
                    return null;// Inavlid char
                }
                catch (IndexOutOfRangeException)
                {
                    c1 = 0;
                    return null;// Inavlid char
                }

                try
                {
                    c2 = ahexval[str[istr++]];
                }
                catch (ArgumentNullException)
                {
                    c2 = 0;
                    return null;// Inavlid char
                }
                catch (ArgumentException)
                {
                    c2 = 0;
                    return null;// Inavlid char
                }
                catch (IndexOutOfRangeException)
                {
                    c2 = 0;
                    return null;// Inavlid char
                }

                result[ir++] = (byte)((c1 << 4) + c2);
            }

            return result;
        }

        public static string BinaryToHex(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            char[] hex = new char[checked(data.Length * 2)];

            for (int i = 0; i < data.Length; i++)
            {
                byte thisByte = data[i];
                hex[2 * i] = NibbleToHex((byte)(thisByte >> 4)); // high nibble
                hex[2 * i + 1] = NibbleToHex((byte)(thisByte & 0xf)); // low nibble
            }

            return new string(hex);
        }

        /// <summary>
        /// Converts a hexadecimal string into its binary representation.
        /// </summary>
        /// <param name="data">The hex string.</param>
        /// <returns>The byte array corresponding to the contents of the hex string,
        /// or null if the input string is not a valid hex string.</returns>
        public static byte[] HexToBinary(string data)
        {
            if (data == null || data.Length % 2 != 0)
            {
                // input string length is not evenly divisible by 2
                return null;
            }

            byte[] binary = new byte[data.Length / 2];

            for (int i = 0; i < binary.Length; i++)
            {
                int highNibble = HexToInt(data[2 * i]);
                int lowNibble = HexToInt(data[2 * i + 1]);

                if (highNibble == -1 || lowNibble == -1)
                {
                    return null; // bad hex data
                }
                binary[i] = (byte)((highNibble << 4) | lowNibble);
            }

            return binary;
        }

        public static int HexToInt(char h)
        {
            return (h >= '0' && h <= '9') ? h - '0' :
            (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
            (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
            -1;
        }

        // converts a nibble (4 bits) to its uppercase hexadecimal character representation [0-9, A-F]
        private static char NibbleToHex(byte nibble)
        {
            return (char)((nibble < 10) ? (nibble + '0') : (nibble - 10 + 'A'));
        }
    }

}
