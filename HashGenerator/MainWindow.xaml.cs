using System.Windows;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using System.Reflection;
using System;
using System.Diagnostics;
using Microsoft.Win32;
using System.IO;

namespace HashGenerator
{
    public partial class MainWindow : Window
    {
        private static readonly string? appName = Assembly.GetExecutingAssembly().GetName().Name;
        #pragma warning disable CS8602 // Deference of a possibly null reference.
        private static readonly Version? appVersion = new(Assembly.GetExecutingAssembly().GetName().Version.ToString(3));
        public MainWindow()
        {
            InitializeComponent();
            HashSelection.SelectedItem = combo_md5;
            mainWindow.Title = $"Hash Generator v{appVersion}";
        }
        public static string GenerateKeccak224(string input)
        {
            KeccakDigest keccak = new(224);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[keccak.GetDigestSize()];
            keccak.BlockUpdate(inputBytes, 0, inputBytes.Length);
            keccak.DoFinal(hashBytes, 0);
            StringBuilder keccakHash = new();
            foreach (byte b in hashBytes)
            {
                keccakHash.Append(b.ToString("X2"));
            }
            return keccakHash.ToString();
        }
        public static string GenerateKeccak256(string input)
        {
            KeccakDigest keccak = new(256);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[keccak.GetDigestSize()];
            keccak.BlockUpdate(inputBytes, 0, inputBytes.Length);
            keccak.DoFinal(hashBytes, 0);
            StringBuilder keccakHash = new();
            foreach (byte b in hashBytes)
            {
                keccakHash.Append(b.ToString("X2"));
            }
            return keccakHash.ToString();
        }
        public static string GenerateKeccak384(string input)
        {
            KeccakDigest keccak = new(384);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[keccak.GetDigestSize()];
            keccak.BlockUpdate(inputBytes, 0, inputBytes.Length);
            keccak.DoFinal(hashBytes, 0);
            StringBuilder keccakHash = new();
            foreach (byte b in hashBytes)
            {
                keccakHash.Append(b.ToString("X2"));
            }
            return keccakHash.ToString();
        }
        public static string GenerateKeccak512(string input)
        {
            KeccakDigest keccak = new(512);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[keccak.GetDigestSize()];
            keccak.BlockUpdate(inputBytes, 0, inputBytes.Length);
            keccak.DoFinal(hashBytes, 0);
            StringBuilder keccakHash = new();
            foreach (byte b in hashBytes)
            {
                keccakHash.Append(b.ToString("X2"));
            }
            return keccakHash.ToString();
        }
        public static string GenerateMD2(string input)
        {
            MD2Digest md2 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[md2.GetDigestSize()];
            md2.BlockUpdate(inputBytes, 0, inputBytes.Length);
            md2.DoFinal(hashBytes, 0);
            StringBuilder md2Hash = new();
            foreach (byte b in hashBytes)
            {
                md2Hash.Append(b.ToString("X2"));
            }
            return md2Hash.ToString();
        }
        public static string GenerateMD4(string input)
        {
            MD4Digest md4 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[md4.GetDigestSize()];
            md4.BlockUpdate(inputBytes, 0, inputBytes.Length);
            md4.DoFinal(hashBytes, 0);
            StringBuilder md4Hash = new();
            foreach (byte b in hashBytes)
            {
                md4Hash.Append(b.ToString("X2"));
            }
            return md4Hash.ToString();
        }
        public static string GenerateMD5(string input)
        {
            MD5Digest md5 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[md5.GetDigestSize()];
            md5.BlockUpdate(inputBytes, 0, inputBytes.Length);
            md5.DoFinal(hashBytes, 0);
            StringBuilder md5Hash = new();
            foreach (byte b in hashBytes)
            {
                md5Hash.Append(b.ToString("X2"));
            }
            return md5Hash.ToString();
        }

        public static string GenerateNTLM(string input)
        {
            //
            // Source Code for the NTLM Hash Generator from https://gist.github.com/withakay/a08aa811c4f2f40243054cd9305efa86
            //
            const uint INIT_A = 0x67452301;
            const uint INIT_B = 0xefcdab89;
            const uint INIT_C = 0x98badcfe;
            const uint INIT_D = 0x10325476;

            const uint SQRT_2 = 0x5a827999;
            const uint SQRT_3 = 0x6ed9eba1;

            char[] itoa16 = new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

            uint[] nt_buffer = new uint[16];
            uint[] output = new uint[4];
            char[] hex_format = new char[32];

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Prepare the string for hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            int i = 0;
            int length = input.Length;
            //The length of input need to be <= 27
            for (; i < length / 2; i++)
            {
                nt_buffer[i] = input[2 * i] | ((uint)input[2 * i + 1] << 16);
            }

            //padding
            if (length % 2 == 1)
            {
                nt_buffer[i] = (uint)input[length - 1] | 0x800000;
            }
            else
            {
                nt_buffer[i] = 0x80;
            }

            //put the length
            nt_buffer[14] = (uint)length << 4;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // NTLM hash calculation
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            uint a = INIT_A;
            uint b = INIT_B;
            uint c = INIT_C;
            uint d = INIT_D;

            /* Round 1 */
            a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

            a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
            d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
            c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
            b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

            /* Round 2 */
            a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

            a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
            d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
            c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
            b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

            /* Round 3 */
            a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

            a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
            d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
            c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
            b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

            output[0] = a + INIT_A;
            output[1] = b + INIT_B;
            output[2] = c + INIT_C;
            output[3] = d + INIT_D;

            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // Convert the hash to hex (for being readable)
            //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            for (i = 0; i < 4; i++)
            {
                int j = 0;
                uint n = output[i];
                //iterate the bytes of the integer
                for (; j < 4; j++)
                {
                    uint convert = n % 256;
                    hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
                    convert /= 16;
                    hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
                    n /= 256;
                }
            }

            return string.Join(string.Empty, hex_format);
        }
        public static string GenerateRIPEMD128(string input)
        {
            RipeMD128Digest ripeMD128 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[ripeMD128.GetDigestSize()];
            ripeMD128.BlockUpdate(inputBytes, 0, inputBytes.Length);
            ripeMD128.DoFinal(hashBytes, 0);
            StringBuilder ripeMD128Hash = new();
            foreach (byte b in hashBytes)
            {
                ripeMD128Hash.Append(b.ToString("X2"));
            }
            return ripeMD128Hash.ToString();
        }
        public static string GenerateRIPEMD160(string input)
        {
            RipeMD160Digest ripeMD160 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[ripeMD160.GetDigestSize()];
            ripeMD160.BlockUpdate(inputBytes, 0, inputBytes.Length);
            ripeMD160.DoFinal(hashBytes, 0);
            StringBuilder ripeMD160Hash = new();
            foreach (byte b in hashBytes)
            {
                ripeMD160Hash.Append(b.ToString("X2"));
            }
            return ripeMD160Hash.ToString();
        }
        public static string GenerateRIPEMD256(string input)
        {
            RipeMD256Digest ripeMD256 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[ripeMD256.GetDigestSize()];
            ripeMD256.BlockUpdate(inputBytes, 0, inputBytes.Length);
            ripeMD256.DoFinal(hashBytes, 0);
            StringBuilder ripeMD256Hash = new();
            foreach (byte b in hashBytes)
            {
                ripeMD256Hash.Append(b.ToString("X2"));
            }
            return ripeMD256Hash.ToString();
        }
        public static string GenerateRIPEMD320(string input)
        {
            RipeMD320Digest ripeMD320 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[ripeMD320.GetDigestSize()];
            ripeMD320.BlockUpdate(inputBytes, 0, inputBytes.Length);
            ripeMD320.DoFinal(hashBytes, 0);
            StringBuilder ripeMD320Hash = new();
            foreach (byte b in hashBytes)
            {
                ripeMD320Hash.Append(b.ToString("X2"));
            }
            return ripeMD320Hash.ToString();
        }
        public static string GenerateSHA1(string input)
        {
            Sha1Digest sha1 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha1.GetDigestSize()];
            sha1.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha1.DoFinal(hashBytes, 0);
            StringBuilder sha1Hash = new();
            foreach (byte b in hashBytes)
            {
                sha1Hash.Append(b.ToString("X2"));
            }
            return sha1Hash.ToString();
        }
        public static string GenerateSHA3(string input)
        {
            Sha3Digest sha3 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha3.GetDigestSize()];
            sha3.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3.DoFinal(hashBytes, 0);
            StringBuilder sha3Hash = new();
            foreach (byte b in hashBytes)
            {
                sha3Hash.Append(b.ToString("X2"));
            }
            return sha3Hash.ToString();
        }
        public static string GenerateSHA224(string input)
        {
            Sha224Digest sha224 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha224.GetDigestSize()];
            sha224.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha224.DoFinal(hashBytes, 0);
            StringBuilder sha224Hash = new();
            foreach (byte b in hashBytes)
            {
                sha224Hash.Append(b.ToString("X2"));
            }
            return sha224Hash.ToString();
        }
        public static string GenerateSHA256(string input)
        {
            Sha256Digest sha256 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha256.GetDigestSize()];
            sha256.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha256.DoFinal(hashBytes, 0);
            StringBuilder sha256Hash = new();
            foreach (byte b in hashBytes)
            {
                sha256Hash.Append(b.ToString("X2"));
            }
            return sha256Hash.ToString();
        }
        public static string GenerateSHA384(string input)
        {
            Sha384Digest sha384 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha384.GetDigestSize()];
            sha384.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha384.DoFinal(hashBytes, 0);
            StringBuilder sha384Hash = new();
            foreach (byte b in hashBytes)
            {
                sha384Hash.Append(b.ToString("X2"));
            }
            return sha384Hash.ToString();
        }
        public static string GenerateSHA512(string input)
        {
            Sha512Digest sha512 = new();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha512.GetDigestSize()];
            sha512.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha512.DoFinal(hashBytes, 0);
            StringBuilder sha512Hash = new();
            foreach (byte b in hashBytes)
            {
                sha512Hash.Append(b.ToString("X2"));
            }
            return sha512Hash.ToString();
        }
        public static string GenerateSHA3_224(string input)
        {
            Sha3Digest sha3_224 = new(224);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha3_224.GetDigestSize()];
            sha3_224.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3_224.DoFinal(hashBytes, 0);
            StringBuilder sha3_224Hash = new();
            foreach (byte b in hashBytes)
            {
                sha3_224Hash.Append(b.ToString("X2"));
            }
            return sha3_224Hash.ToString();
        }
        public static string GenerateSHA3_256(string input)
        {
            Sha3Digest sha3_256 = new(256);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha3_256.GetDigestSize()];
            sha3_256.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3_256.DoFinal(hashBytes, 0);
            StringBuilder sha3_256Hash = new();
            foreach (byte b in hashBytes)
            {
                sha3_256Hash.Append(b.ToString("X2"));
            }
            return sha3_256Hash.ToString();
        }
        public static string GenerateSHA3_384(string input)
        {
            Sha3Digest sha3_384 = new(384);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha3_384.GetDigestSize()];
            sha3_384.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3_384.DoFinal(hashBytes, 0);
            StringBuilder sha3_384Hash = new();
            foreach (byte b in hashBytes)
            {
                sha3_384Hash.Append(b.ToString("X2"));
            }
            return sha3_384Hash.ToString();
        }
        public static string GenerateSHA3_512(string input)
        {
            Sha3Digest sha3_512 = new(512);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[sha3_512.GetDigestSize()];
            sha3_512.BlockUpdate(inputBytes, 0, inputBytes.Length);
            sha3_512.DoFinal(hashBytes, 0);
            StringBuilder sha3_512Hash = new();
            foreach (byte b in hashBytes)
            {
                sha3_512Hash.Append(b.ToString("X"));
            }
            return sha3_512Hash.ToString();
        }
        public static string GenerateSHAKE128(string input)
        {
            ShakeDigest shake128 = new(128);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[shake128.GetDigestSize()];
            shake128.BlockUpdate(inputBytes, 0, inputBytes.Length);
            shake128.DoFinal(hashBytes, 0);
            StringBuilder shake128Hash = new();
            foreach (byte b in hashBytes)
            {
                shake128Hash.Append(b.ToString("X"));
            }
            return shake128Hash.ToString();
        }
        public static string GenerateSHAKE256(string input)
        {
            ShakeDigest shake256 = new(256);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = new byte[shake256.GetDigestSize()];
            shake256.BlockUpdate(inputBytes, 0, inputBytes.Length);
            shake256.DoFinal(hashBytes, 0);
            StringBuilder shake256Hash = new();
            foreach (byte b in hashBytes)
            {
                shake256Hash.Append(b.ToString("X"));
            }
            return shake256Hash.ToString();
        }
        public void GenerateHashes(object sender, RoutedEventArgs e)
        {
            HashBox.Clear();
            string generatedHash = "";
            string selection = HashSelection.Text;
            foreach (string line in TextEntryBox.Text.Split("\n"))
            {
                string textLine = line.TrimEnd();
                if (selection == "Keccak-224")
                {
                    generatedHash = GenerateKeccak224(textLine);
                }
                else if (selection == "Keccak-256")
                {
                    generatedHash = GenerateKeccak256(textLine);
                }
                else if (selection == "Keccak-384")
                {
                    generatedHash = GenerateKeccak384(textLine);
                }
                else if (selection == "Keccak-512")
                {
                    generatedHash = GenerateKeccak512(textLine);
                }
                else if (selection == "MD2")
                {
                    generatedHash = GenerateMD2(textLine);
                }
                else if (selection == "MD4")
                {
                    generatedHash = GenerateMD4(textLine);
                }
                else if (selection == "MD5")
                {
                    generatedHash = GenerateMD5(textLine);
                }
                else if (selection == "NTLM")
                {
                    generatedHash = GenerateNTLM(textLine);
                }
                else if (selection == "RIPEMD128")
                {
                    generatedHash = GenerateRIPEMD128(textLine);
                }
                else if (selection == "RIPEMD160")
                {
                    generatedHash = GenerateRIPEMD160(textLine);
                }
                else if (selection == "RIPEMD256")
                {
                    generatedHash = GenerateRIPEMD256(textLine);
                }
                else if (selection == "RIPEMD320")
                {
                    generatedHash = GenerateRIPEMD320(textLine);
                }
                else if (selection == "SHA1")
                {
                    generatedHash = GenerateSHA1(textLine);
                }
                else if (selection == "SHA3")
                {
                    generatedHash = GenerateSHA3(textLine);
                }
                else if (selection == "SHA224")
                {
                    generatedHash = GenerateSHA224(textLine);
                }
                else if (selection == "SHA256")
                {
                    generatedHash = GenerateSHA256(textLine);
                }
                else if (selection == "SHA384")
                {
                    generatedHash = GenerateSHA384(textLine);
                }
                else if (selection == "SHA512")
                {
                    generatedHash = GenerateSHA512(textLine);
                }
                else if (selection == "SHA3-224")
                {
                    generatedHash = GenerateSHA3_224(textLine);
                }
                else if (selection == "SHA3-256")
                {
                    generatedHash = GenerateSHA3_256(textLine);
                }
                else if (selection == "SHA3-384")
                {
                    generatedHash = GenerateSHA3_384(textLine);
                }
                else if (selection == "SHA3-512")
                {
                    generatedHash = GenerateSHA3_512(textLine);
                }
                else if (selection == "SHAKE128")
                {
                    generatedHash = GenerateSHAKE128(textLine);
                }
                else if (selection == "SHAKE256")
                {
                    generatedHash = GenerateSHAKE256(textLine);
                }
                if (HashCase.IsChecked == false)
                    generatedHash = generatedHash.ToLower();
                else generatedHash = generatedHash.ToUpper();
                HashBox.AppendText(generatedHash + "\n");
            }

        }
        public void ClearResults(object sender, RoutedEventArgs e)
        { 
            HashBox.Clear();
            TextEntryBox.Clear();
        }
        private void ShowAbout(object sender, RoutedEventArgs e)
        // Shows the About box
        {
            MessageBoxResult result = MessageBox.Show(
                $"Hash Generator v{appVersion}\n" +
                $"Author: Corey Forman (digitalsleuth)\n" +
                $"Source: https://github.com/digitalsleuth/hash-generator\n\n" +
                $"Would you like to visit the repo on GitHub?",
                $"Hash Generator v{appVersion}", MessageBoxButton.YesNoCancel, MessageBoxImage.Information);
            if (result == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo($"https://github.com/digitalsleuth/hash-generator") { UseShellExecute = true });
            }
        }
        private void SaveResults(object sender, RoutedEventArgs e)
        {
            FileSave();
        }
        private void FileSave()
        // Save the contents of the Hash Text Box as a Text File
        {
            try
            {
                SaveFileDialog saveFileDialog = new()
                {
                    Filter = "Text File | *.txt"
                };
                if (saveFileDialog.ShowDialog() == true)
                    File.WriteAllText(saveFileDialog.FileName, HashBox.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"[ERROR] Unable to launch the Save File dialog:\n{ex}");
            }
        }
        private void FileExitClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

    }
}
