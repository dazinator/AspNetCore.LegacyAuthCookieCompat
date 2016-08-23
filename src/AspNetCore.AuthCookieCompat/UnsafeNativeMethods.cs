using System.Runtime.InteropServices;

namespace AspNetCore.LegacyAuthCookieCompat
{
    [ComVisible(false)]
    internal static class UnsafeNativeMethods
    {
      
        [DllImport("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\webengine4.dll")]
        internal static extern int GetHMACSHA1Hash(byte[] data1, int dataOffset1, int dataSize1, byte[] data2, int dataSize2, byte[] innerKey, int innerKeySize, byte[] outerKey, int outerKeySize, byte[] hash, int hashSize);

      
        [DllImport("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\webengine4.dll", CharSet = CharSet.Unicode)]
        internal static extern int CookieAuthConstructTicket(byte[] pData,
                                                            int iDataLen,
                                                            string szName,
                                                            string szData,
                                                            string szPath,
                                                            byte[] pBytes,
                                                            long[] pDates);
       

        [DllImport("webengine4.dll")]
        internal static extern int GetSHA1Hash(byte[] data, int dataSize, byte[] hash, int hashSize);

    }
}
