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
            encrypt("", "hola", 256);
        }

        static void encrypt(string plaintext, string password, int nBits)
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
            //key = key.concat(key.slice(0, nBytes - 16));  // expand key to 16/24/32 bytes long
            Console.WriteLine("");
        }

    }
}
