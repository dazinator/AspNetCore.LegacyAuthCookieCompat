using System;
using System.Runtime.InteropServices;

namespace AspNetCore.LegacyAuthCookieCompat
{
    [ComVisible(false)]
    internal static class UnsafeNativeMethods
    {

        [DllImport("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\webengine4.dll", EntryPoint = "GetHMACSHA1Hash")]
        internal static extern int GetHMACSHA1Hash_x86(byte[] data1, int dataOffset1, int dataSize1, byte[] data2, int dataSize2, byte[] innerKey, int innerKeySize, byte[] outerKey, int outerKeySize, byte[] hash, int hashSize);


        [DllImport("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\webengine4.dll", EntryPoint = "CookieAuthConstructTicket", CharSet = CharSet.Unicode)]
        internal static extern int CookieAuthConstructTicket_x86(byte[] pData, int iDataLen, string szName, string szData, string szPath, byte[] pBytes, long[] pDates);


        [DllImport("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\webengine4.dll", EntryPoint = "GetSHA1Hash")]
        internal static extern int GetSHA1Hash_x86(byte[] data, int dataSize, byte[] hash, int hashSize);



        [DllImport("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\webengine4.dll", EntryPoint = "GetHMACSHA1Hash")]
        internal static extern int GetHMACSHA1Hash_x64(byte[] data1, int dataOffset1, int dataSize1, byte[] data2, int dataSize2, byte[] innerKey, int innerKeySize, byte[] outerKey, int outerKeySize, byte[] hash, int hashSize);


        [DllImport("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\webengine4.dll", EntryPoint = "CookieAuthConstructTicket", CharSet = CharSet.Unicode)]
        internal static extern int CookieAuthConstructTicket_x64(byte[] pData, int iDataLen, string szName, string szData, string szPath, byte[] pBytes, long[] pDates);


        [DllImport("C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\webengine4.dll", EntryPoint = "GetSHA1Hash")]
        internal static extern int GetSHA1Hash_x64(byte[] data, int dataSize, byte[] hash, int hashSize);



        public static int GetSHA1Hash(byte[] data, int dataSize, byte[] hash, int hashSize)
        {
            if (Environment.Is64BitProcess)
            {
                return GetSHA1Hash_x64(data, dataSize, hash, hashSize);
            }
            else
            {
                return GetSHA1Hash_x86(data, dataSize, hash, hashSize);
            }
        }


        public static int CookieAuthConstructTicket(byte[] pData, int iDataLen, string szName, string szData, string szPath, byte[] pBytes, long[] pDates)
        {
            if (Environment.Is64BitProcess)
            {
                return CookieAuthConstructTicket_x64(pData, iDataLen, szName, szData, szPath, pBytes, pDates);
            }
            else
            {
                return CookieAuthConstructTicket_x86(pData, iDataLen, szName, szData, szPath, pBytes, pDates);
            }

        }


        public static int GetHMACSHA1Hash(byte[] data1, int dataOffset1, int dataSize1, byte[] data2, int dataSize2,
            byte[] innerKey, int innerKeySize, byte[] outerKey, int outerKeySize, byte[] hash, int hashSize)
        {
            if (Environment.Is64BitProcess)
            {
                return GetHMACSHA1Hash_x64(data1, dataOffset1, dataSize1, data2, dataSize2, innerKey, innerKeySize, outerKey, outerKeySize, hash, hashSize);
            }
            else
            {
                return GetHMACSHA1Hash_x86(data1, dataOffset1, dataSize1, data2, dataSize2, innerKey, innerKeySize, outerKey, outerKeySize, hash, hashSize);
            }
        }

        //[DllImport("MyDll32.dll", EntryPoint = "Func1", CallingConvention = CallingConvention.Cdecl)]
        //private static extern int Func1_32(int var1, int var2);

        //[DllImport("MyDll64.dll", EntryPoint = "Func1", CallingConvention = CallingConvention.Cdecl)]
        //private static extern int Func1_64(int var1, int var2);

        //public static int Func1(int var1, int var2)
        //{
        //    return IntPtr.Size == 8 /* 64bit */ ? Func1_64(var1, var2) : Func1_32(var1, var2);
        //}

    }
}
