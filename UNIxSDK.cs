using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Pastel;

namespace UNIx.SDK
{
    public class UNIxSDK
    {
        public class TCPRequest
        {
            public string Path
            {
                get; set;
            } = "/";
            public Dictionary<string, string> Data { get; set; } = new Dictionary<string, string>();
        }
        public static string GenerateToken()
        {
            // Thread-safe and returns a UUID
            return Guid.NewGuid().ToString();
        }

        public static string GenerateUserId()
        {
            // Format: usr.A1DASC-DASQD-SADASQD
            return "usr." + RandomBlock(6) + "-" + RandomBlock(5) + "-" + RandomBlock(6);
        }

        private static string RandomBlock(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Span<byte> bytes = stackalloc byte[length];
            RandomNumberGenerator.Fill(bytes);

            char[] block = new char[length];
            for (int i = 0; i < length; i++)
                block[i] = chars[bytes[i] % chars.Length];

            return new string(block);
        }
        public enum LogLevel
        {
            Info,
            Warning,
            Error,
            Debug,
            Trace
        }
        public enum AuthenticationType : byte
        {
            Fire,
            Heartbeat
        }
        public enum MessageType : byte
        {
            AuthRequest = 0x01,
            AuthData = 0x02,
            ClientInformation = 0x03,
            Heartbeat = 0x04,
            RequestProduct = 0x05,


            AuthSuccess = 0x10,
            AuthFailure = 0x11,
            ServerMessage = 0x12,
            InvalidHeartbeat = 0x13,
            ProductData = 0x14,
            InvalidProductData = 0x15,

            ConnectionClose = 0x20,
            Administration = 0x21,

            BinaryData = 0x30,
            BinaryHeader = 0x31,
            BinaryEnd = 0x32,
        }

        private static readonly byte[] KeyBytes = new byte[]
        {
            0x9F, 0xB2, 0x43, 0x77, 0xC1, 0xDE, 0x5A, 0x10,
            0x6C, 0x89, 0xFE, 0x34, 0xAB, 0x02, 0xD7, 0xE3
        };

        public const ushort ConnectionPort = 8148;

        private static bool IsPrintableUnicode(int codePoint)
        {
            return (codePoint >= 0x20 && codePoint <= 0xD7FF);
        }
        public static string ConsoleFormat(byte[] data)
        {

            var sb = new StringBuilder();
            var enumerator = StringInfo.GetTextElementEnumerator(Encoding.UTF8.GetString(data));

            while (enumerator.MoveNext())
            {
                var element = enumerator.GetTextElement();
                int codePoint = char.ConvertToUtf32(element, 0);
                if (IsPrintableUnicode(codePoint))
                    sb.Append(element);
            }
            return sb.ToString();
        }
        public static string ConsoleKey(byte[] key) =>
            "UNIx::ConsoleKey::" + ConsoleFormat(key);

        public static byte[] GenerateKey()
        {
            var sb = new StringBuilder(32);
            using var rng = RandomNumberGenerator.Create();
            var buffer = new byte[4];

            int count = 0;
            while (count < 32)
            {
                rng.GetBytes(buffer);
                int roll = buffer[0] % 100; // 0–99

                if (roll < 70)
                {
                    int asciiChar = 0;
                    do
                    {
                        rng.GetBytes(buffer);
                        asciiChar = buffer[0] % 95 + 32;
                    }
                    while (!char.IsLetterOrDigit((char)asciiChar) && !char.IsPunctuation((char)asciiChar));

                    sb.Append((char)asciiChar);
                }
                else
                {
                    int codePoint;
                    do
                    {
                        rng.GetBytes(buffer);
                        codePoint = BitConverter.ToInt32(buffer, 0) & 0x1FFFFF;
                    }
                    while (!IsPrintableUnicode(codePoint) || codePoint < 32);

                    sb.Append(char.ConvertFromUtf32(codePoint));
                }

                count++;
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        public static class Protocol
        {
            public const int HeaderSize = 5;
            public static byte[] PackBytes(MessageType type, byte[] payload, byte[] key = null)
            {
                var compressedPayload = Compress(payload);
                var length = BitConverter.GetBytes(compressedPayload.Length);
                var buffer = new byte[HeaderSize + compressedPayload.Length];

                buffer[0] = (byte)type;
                Array.Copy(length, 0, buffer, 1, 4);
                Array.Copy(compressedPayload, 0, buffer, 5, compressedPayload.Length);

                return EncryptDecrypt(buffer, key ?? KeyBytes);
            }
            public static byte[] Pack(MessageType type, string message, byte[] key = null) =>
                PackBytes(type, Encoding.UTF8.GetBytes(message), key);

            public static (MessageType type, string message)? Unpack(byte[] buffer, int bytesRead, byte[] key = null)
            {
                if (buffer == null || buffer.Length == 0 || bytesRead <= 0)
                    return null;

                if (bytesRead < HeaderSize)
                    return null;

                var decrypted = EncryptDecrypt(buffer[..bytesRead], key ?? KeyBytes);

                if (decrypted.Length < HeaderSize)
                    return null;

                var typeByte = decrypted[0];
                if (!Enum.IsDefined(typeof(MessageType), typeByte))
                    return null;

                var type = (MessageType)typeByte;

                int length = BitConverter.ToInt32(decrypted, 1);
                if (length < 0 || length > 1_000_000) // max 1MB
                    return null;

                if (decrypted.Length < HeaderSize + length)
                    return null;

                var compressedData = new byte[length];
                Buffer.BlockCopy(decrypted, HeaderSize, compressedData, 0, length);

                var decompressed = Decompress(compressedData);
                if (decompressed == null)
                    return null;

                return (type, Encoding.UTF8.GetString(decompressed));
            }
            public static (MessageType type, byte[] message)? UnpackBytes(byte[] buffer, int bytesRead, byte[] key = null)
            {
                if (buffer == null || buffer.Length == 0 || bytesRead <= 0)
                    return null;

                if (bytesRead < HeaderSize)
                    return null;

                var decrypted = EncryptDecrypt(buffer[..bytesRead], key ?? KeyBytes);

                if (decrypted.Length < HeaderSize)
                    return null;

                var typeByte = decrypted[0];
                if (!Enum.IsDefined(typeof(MessageType), typeByte))
                    return null;

                var type = (MessageType)typeByte;

                int length = BitConverter.ToInt32(decrypted, 1);
                if (length < 0 || length > 1_000_000) 
                    return null;

                if (decrypted.Length < HeaderSize + length)
                    return null;

                var compressedData = new byte[length];
                Buffer.BlockCopy(decrypted, HeaderSize, compressedData, 0, length);

                var decompressed = Decompress(compressedData);
                if (decompressed == null)
                    return null;

                return (type, decompressed);
            }

            private static byte[] Compress(byte[] data)
            {
                if (data.Length <= 128)
                {
                    var result = new byte[data.Length + 1];
                    result[0] = 0;
                    Buffer.BlockCopy(data, 0, result, 1, data.Length);
                    return result;
                }

                using var output = new MemoryStream();
                output.WriteByte(1);
                using (var gzip = new GZipStream(output, CompressionLevel.Optimal))
                    gzip.Write(data, 0, data.Length);
                return output.ToArray();
            }
            private static byte[] Decompress(byte[] data)
            {
                if (data.Length == 0)
                    return Array.Empty<byte>();

                if (data[0] == 0)
                {
                    var result = new byte[data.Length - 1];
                    Buffer.BlockCopy(data, 1, result, 0, result.Length);
                    return result;
                }

                using var input = new MemoryStream(data, 1, data.Length - 1);
                using var gzip = new GZipStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                gzip.CopyTo(output);
                return output.ToArray();
            }
        }

        public static byte[] EncryptDecrypt(byte[] data, byte[] key)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }
        public static byte[] EncryptString(string input, byte[] key) =>
            EncryptDecrypt(Encoding.UTF8.GetBytes(input), key);

        private static bool LogEnabled = true;
        private static LogLevel MinLogLevel = LogLevel.Trace;
        private static bool LogTimeDate = true;
        public static void DebugMode(bool value) =>
            LogEnabled = value; 

        public static void SetLoggingMode(LogLevel value) =>
            MinLogLevel = value;
        public static void SetLogDateTime(bool value) =>
            LogTimeDate = value;


        private static string ParseLog(string message)
        {
            // Highlight [*] tags in orange
            message = Regex.Replace(message, @"^(?:\s*|\[)(\[[\x20-\x7E]*?\])", match =>
     match.Groups[1].Value.Pastel(Color.Orange), RegexOptions.None, TimeSpan.FromMilliseconds(100));


            // Highlight keywords
            message = Regex.Replace(message, @"\b(error|fail(ed)?|exception)\b", match =>
                match.Value.Pastel(Color.Red), RegexOptions.IgnoreCase);
            message = Regex.Replace(message, @"\b(success|done|complete(d)?)\b", match =>
                match.Value.Pastel(Color.LimeGreen), RegexOptions.IgnoreCase);
            message = Regex.Replace(message, @"\b(warning|caution|alert)\b", match =>
                match.Value.Pastel(Color.Yellow), RegexOptions.IgnoreCase);

            return message;
        }

        public static void Log(LogLevel level, string message)
        {
            if (!LogEnabled || Console.OpenStandardOutput() == Stream.Null)
                return;

            if (level > MinLogLevel)
                return;

            string prefix = LogTimeDate
                ? $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] "
                : string.Empty;

            ConsoleColor originalColor = Console.ForegroundColor;

            switch (level)
            {
                case LogLevel.Info:
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"{prefix}[INFO]  {ParseLog(message)}");
                    break;
                case LogLevel.Warning:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"{prefix}[WARN]  {ParseLog(message)}");
                    break;
                case LogLevel.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"{prefix}[ERROR] {ParseLog(message)}");
                    break;
                case LogLevel.Debug:
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"{prefix}[DEBUG] {ParseLog(message)}");
                    break;
                case LogLevel.Trace:
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine($"{prefix}[TRACE] {ParseLog(message)}");
                    break;
            }

            Console.ForegroundColor = originalColor;
        }

        public static void LogInfo(string message) => Log(LogLevel.Info, message);
        public static void LogWarn(string message) => Log(LogLevel.Warning, message);
        public static void LogError(string message) => Log(LogLevel.Error, message);
        public static void LogDebug(string message) => Log(LogLevel.Debug, message);
        public static void LogTrace(string message) => Log(LogLevel.Trace, message);

        public static class SystemInformationn
        {
            private static readonly string DllPath = Path.Combine(Path.GetTempPath(), "UNIxNative.dll");
            private static IntPtr hModule;

            [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary(string lpFileName);

            [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate IntPtr GetStringDelegate();
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate void InitializeDelegate();

            private static readonly InitializeDelegate _initialize;

            private static readonly GetStringDelegate _biosVendor;
            private static readonly GetStringDelegate _biosVersion;
            private static readonly GetStringDelegate _biosDate;

            private static readonly GetStringDelegate _chassisManufacturer;
            private static readonly GetStringDelegate _chassisVersion;
            private static readonly GetStringDelegate _chassisSerial;

            private static readonly GetStringDelegate _systemManufacturer;
            private static readonly GetStringDelegate _systemProduct;
            private static readonly GetStringDelegate _systemVersion;
            private static readonly GetStringDelegate _systemSerial;
            private static readonly GetStringDelegate _systemSKU;
            private static readonly GetStringDelegate _systemFamily;
            private static readonly GetStringDelegate _systemUUID;

            private static readonly GetStringDelegate _baseboardManufacturer;
            private static readonly GetStringDelegate _baseboardProduct;
            private static readonly GetStringDelegate _baseboardSerial;

            private static readonly GetStringDelegate _cpuProduct;
            private static readonly GetStringDelegate _cpuSerial;

            private static readonly GetStringDelegate _macAddressMain;
            private static readonly GetStringDelegate _systemHWID;

            public static string BIOS_Vendor
            {
                get;
            }
            public static string BIOS_Version
            {
                get;
            }
            public static string BIOS_Date
            {
                get;
            }

            public static string Chassis_Manufacturer
            {
                get;
            }
            public static string Chassis_Version
            {
                get;
            }
            public static string Chassis_Serial
            {
                get;
            }

            public static string System_Manufacturer
            {
                get;
            }
            public static string System_Product
            {
                get;
            }
            public static string System_Version
            {
                get;
            }
            public static string System_Serial
            {
                get;
            }
            public static string System_SKU
            {
                get;
            }
            public static string System_Family
            {
                get;
            }
            public static string System_UUID
            {
                get;
            }

            public static string Baseboard_Manufacturer
            {
                get;
            }
            public static string Baseboard_Product
            {
                get;
            }
            public static string Baseboard_Serial
            {
                get;
            }

            public static string CPU_Product
            {
                get;
            }
            public static string CPU_Serial
            {
                get;
            }

            public static string MACAddress_Main
            {
                get;
            }
            public static string System_HWID
            {
                get;
            }

            static SystemInformationn()
            {
                if (!File.Exists(DllPath))
                    File.WriteAllBytes(DllPath, Resources.UNIxNative);
                hModule = LoadLibrary(DllPath);
                if (hModule == IntPtr.Zero)
                    throw new Exception("Failed to load DLL: " + DllPath);

                _biosVendor = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "BIOS_Vendor"));
                _biosVersion = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "BIOS_Version"));
                _biosDate = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "BIOS_Date"));

                _chassisManufacturer = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Chassis_Manufacturer"));
                _chassisVersion = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Chassis_Version"));
                _chassisSerial = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Chassis_Serial"));

                _systemManufacturer = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_Manufacturer"));
                _systemProduct = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_Product"));
                _systemVersion = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_Version"));
                _systemSerial = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_Serial"));
                _systemSKU = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_SKU"));
                _systemFamily = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_Family"));
                _systemUUID = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_UUID"));

                _baseboardManufacturer = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Baseboard_Manufacturer"));
                _baseboardProduct = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Baseboard_Product"));
                _baseboardSerial = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "Baseboard_Serial"));

                _cpuProduct = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "CPU_Product"));
                _cpuSerial = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "CPU_Serial"));

                _macAddressMain = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "MACAddress_Main"));
                _systemHWID = Marshal.GetDelegateForFunctionPointer<GetStringDelegate>(GetProcAddress(hModule, "System_HWID"));

                Baseboard_Serial = Marshal.PtrToStringAnsi(_baseboardSerial()) ?? ""; // some weird error unless first
                Baseboard_Manufacturer = Marshal.PtrToStringAnsi(_baseboardManufacturer()) ?? "";
                Baseboard_Product = Marshal.PtrToStringAnsi(_baseboardProduct()) ?? "";

                BIOS_Vendor = Marshal.PtrToStringAnsi(_biosVendor()) ?? "";
                BIOS_Version = Marshal.PtrToStringAnsi(_biosVersion()) ?? "";
                BIOS_Date = Marshal.PtrToStringAnsi(_biosDate()) ?? "";

                Chassis_Manufacturer = Marshal.PtrToStringAnsi(_chassisManufacturer()) ?? "";
                Chassis_Version = Marshal.PtrToStringAnsi(_chassisVersion()) ?? "";
                Chassis_Serial = Marshal.PtrToStringAnsi(_chassisSerial()) ?? "";

                System_Manufacturer = Marshal.PtrToStringAnsi(_systemManufacturer()) ?? "";
                System_Product = Marshal.PtrToStringAnsi(_systemProduct()) ?? "";
                System_Version = Marshal.PtrToStringAnsi(_systemVersion()) ?? "";
                System_Serial = Marshal.PtrToStringAnsi(_systemSerial()) ?? "";
                System_SKU = Marshal.PtrToStringAnsi(_systemSKU()) ?? "";
                System_Family = Marshal.PtrToStringAnsi(_systemFamily()) ?? "";
                System_UUID = Marshal.PtrToStringAnsi(_systemUUID()) ?? "";


                CPU_Product = Marshal.PtrToStringAnsi(_cpuProduct()) ?? "";
                CPU_Serial = Marshal.PtrToStringAnsi(_cpuSerial()) ?? "";

                MACAddress_Main = Marshal.PtrToStringAnsi(_macAddressMain()) ?? "";
                System_HWID = Marshal.PtrToStringAnsi(_systemHWID()) ?? "";
            }
        }
    }
}
