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
            string encriptado = encrypt("hola", "hola", 256);
            string decriptado = decrypt(encriptado, "hola", 256);
            Console.WriteLine(encriptado);
            Console.WriteLine(decriptado);
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
            Console.WriteLine(ctrTxt + ciphertext);
            ciphertext = Base64Encode( ctrTxt + ciphertext);
            

            return ciphertext;
        }

        /**
     * Decrypt a text encrypted by AES in counter mode of operation
     *
     * @param   {string} ciphertext - Cipher text to be decrypted.
     * @param   {string} password - Password to use to generate a key for decryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Decrypted text
     *
     * @example
     *   const decr = AesCtr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
     */
        static string decrypt(string ciphertext,string password,int nBits)
        {
            const int blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
            if (!(nBits == 128 || nBits == 192 || nBits == 256))
            {
                Console.WriteLine("Key size is not 128 / 192 / 256");
            }
            ciphertext = Base64Decode(ciphertext);
            Console.WriteLine(ciphertext);
            // use AES to encrypt password (mirroring encrypt routine)
            int nBytes = nBits / 8;  // no bytes in key
            byte[] pwBytes = new byte[(nBytes)];
            for (int i = 0; i < nBytes; i++)
            {  // use 1st nBytes chars of password for key
                pwBytes[i] = i < password.Length ? Convert.ToByte(password[(i)]) : Convert.ToByte(0);
            }

            Aes aes = new Aes();
            byte[] key = aes.cipher(pwBytes, aes.keyExpansion(pwBytes));
            key = key.Concat(key.Slice(0, nBytes - 16)).ToArray();  // expand key to 16/24/32 bytes long

            // recover nonce from 1st 8 bytes of ciphertext
            byte[] counterBlock = new byte[10000];
            string ctrTxt = ciphertext.Slice(0, 8);
            for (int i = 0; i < 8; i++) counterBlock[i] = Convert.ToByte(ctrTxt[(i)]);

            // generate key schedule
            byte[,] keySchedule = aes.keyExpansion(key);

            // separate ciphertext into blocks (skipping past initial 8 bytes)
            double nBlocks = Math.Ceiling((double)(ciphertext.Length - 8) / blockSize);
            string[] ct = new string[((int)nBlocks)];
            for (int b = 0; b < nBlocks; b++) ct[b] = ciphertext.Slice(8 + b * blockSize, 8 + b * blockSize + blockSize);
            string[] ciphertext1 = ct;  // ciphertext is now array of block-length strings

            // plaintext will get generated block-by-block into array of block-length strings
            string plaintext = "";

            for (int b = 0; b < nBlocks; b++)
            {
                // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
                for (int c = 0; c < 4; c++)
                {
                    byte byte1 = Convert.ToByte(((uint)(b) >> c * 8) & 0xff);
                    counterBlock[15 - c] = Convert.ToByte(((uint)(b) >> c * 8) & 0xff);
                }
                for (int c = 0; c < 4; c++)
                {
                    double byte1 = ( (double)(b + 1) / 0x100000000 - 1);
                    byte byte2 = Convert.ToByte(((uint)byte1 >> c * 8) & 0xff);
                    counterBlock[15 - c - 4] = byte2;
                }

                byte[] cipherCntr = aes.cipher(counterBlock, keySchedule);  // encrypt counter block

                char[] plaintxtByte = new char[(ciphertext1[b].Length)];
                for (int i = 0; i < ciphertext1[b].Length; i++)
                {
                    // -- xor plaintext with ciphered counter byte-by-byte --
                    plaintxtByte[i] = Convert.ToChar(cipherCntr[i] ^ Convert.ToByte( ciphertext1[b][(i)]));
                }
                plaintext = plaintext + string.Join("",plaintxtByte);
                
            }
            return plaintext;
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

        /// <summary>
        /// Get the string slice between the two indexes.
        /// Inclusive for start index, exclusive for end index.
        /// </summary>
        public static string Slice(this string source, int start, int end)
        {
            if (end < 0) // Keep this for negative end support
            {
                end = source.Length + end;
            }
            if (end > source.Length) end = source.Length;
            int len = end - start;               // Calculate length
            return source.Substring(start, len); // Return Substring of length
        }
    }
    
}
