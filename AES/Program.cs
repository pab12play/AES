using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(encrypt("hola", "hola", 256));
            Console.ReadLine();
        }

        static string encrypt(string plaintext, string password, int nBits)
        {
            const int blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
            if (!(nBits == 128 || nBits == 192 || nBits == 256))
            {
                Console.WriteLine("Key size is not 128 / 192 / 256");
            }

            // use AES itself to encrypt password to get cipher key (using plain password as source for key
            // expansion) to give us well encrypted key (in real use hashed password could be used for key)
            int nBytes = nBits / 8;  // no bytes in key (16/24/32)
            byte[] pwBytes = new byte[nBytes];
            for (int i = 0; i < nBytes; i++)
            {  // use 1st 16/24/32 chars of password for key
                pwBytes[i] = i < password.Length ? Convert.ToByte(password[i]) : (byte)0;
            }

            Aes aes = new Aes();
            byte[] key = aes.cipher(pwBytes, aes.keyExpansion(pwBytes)); // gives us 16-byte key
            key = key.Concat(key.Slice(0, nBytes - 16)).ToArray();  // expand key to 16/24/32 bytes long


            // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
            // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
            byte[] counterBlock = new byte[(blockSize)];

            uint nonce = 0, nonceMs = 0, nonceSec = 0, nonceRnd = 0;

            for (int i = 0; i < 2; i++) counterBlock[i] = Convert.ToByte((nonceMs >> i * 8) & 0xff);
            for (int i = 0; i < 2; i++) counterBlock[i + 2] = Convert.ToByte((nonceRnd >> i * 8) & 0xff);
            for (int i = 0; i < 4; i++) counterBlock[i + 4] = Convert.ToByte((nonceSec >> i * 8) & 0xff);

            // and convert it to a string to go on the front of the ciphertext
            string ctrTxt = "";
            for (int i = 0; i < 8; i++) ctrTxt += (char)counterBlock[i];

            // generate key schedule - an expansion of the key into distinct Key Rounds for each round
            byte[,] keySchedule = aes.keyExpansion(key);

            double blockCount = Math.Ceiling(((double)plaintext.Length / blockSize));
            string ciphertext = "";

            for (int b = 0; b < blockCount; b++)
            {
                // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
                // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
                for (int c = 0; c < 4; c++) counterBlock[15 - c] = Convert.ToByte((uint)(b >> c * 8) & 0xff);
                for (int c = 0; c < 4; c++) counterBlock[15 - c - 4] = Convert.ToByte((uint)(b / 0x100000000 >> c * 8));

                byte[] cipherCntr = aes.cipher(counterBlock, keySchedule);  // -- encrypt counter block --

                // block size is reduced on final block
                int blockLength = b < blockCount - 1 ? blockSize : (plaintext.Length - 1) % blockSize + 1;
                char[] cipherChar = new char[(blockLength)];

                for (int i= 0; i < blockLength; i++)
                {
                    // -- xor plaintext with ciphered counter char-by-char --
                    cipherChar[i] = Convert.ToChar(cipherCntr[i] ^ plaintext[(b * blockSize + i)]);
                    cipherChar[i] = (cipherChar[i]);
                }
                ciphertext = ciphertext + string.Join("",cipherChar);
            }
            ciphertext = Base64Encode( ctrTxt + ciphertext);

            return ciphertext;
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }

    public static class Extensions
    {
        /// <summary>
        /// Get the array slice between the two indexes.
        /// ... Inclusive for start index, exclusive for end index.
        /// </summary>
        public static T[] Slice<T>(this T[] source, int start, int end)
        {
            // Handles negative ends.
            if (end < 0)
            {
                end = source.Length + end;
            }
            int len = end - start;

            // Return new array.
            T[] res = new T[len];
            for (int i = 0; i < len; i++)
            {
                res[i] = source[i + start];
            }
            return res;
        }
    }
}
