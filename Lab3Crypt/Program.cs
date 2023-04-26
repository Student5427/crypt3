using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Aes_Example
{
    class AesExample
    {
        public static void Main()
        {
            string original = "Here is some data to encrypt!";

            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            /*using (Aes myAes = Aes.Create())
            {

                // Encrypt the string to an array of bytes.
                byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

                // Decrypt the bytes to a string.
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Round Trip: {0}", roundtrip);
            }*/

            byte[] key = GetKey("секретный ключ");
            byte[] IV = GetIV("вектор");

            //DecryptFile("secretfile.enc", "decrypt.txt", key, IV);
        }

        private static byte[] GetIV(string ivSecret)
        {
            using MD5 md5 = MD5.Create();
            return md5.ComputeHash(Encoding.UTF8.GetBytes(ivSecret));
        }
        private static byte[] GetKey(string key)
        {
            using SHA256 sha256 = SHA256.Create();
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
        }
        /*static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            return encrypted;

        }
        */
        static void Encrypt(string[] args)
        {
            string sourceFileName = "secretfile.txt"; //файл, который будем шифровать
            string outputFileName = "secretfile.enc"; //файл, который будет содержать зашифрованные данные
            string key = "секретный ключ"; //ключ для шифрования
            string ivSecret = "вектор"; //вектор инициализации
            using Aes aes = Aes.Create();
            aes.IV = GetIV(ivSecret);
            aes.Key = GetKey(key);
            using FileStream inStream = new FileStream(sourceFileName, FileMode.Open); //создаем файловый поток на чтение
            using FileStream outStream = new FileStream(outputFileName, FileMode.Create);//создаем файловый поток на запись
                                                                                         //поток для шифрования данных
            CryptoStream encStream = new CryptoStream(outStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write);
            long readTotal = 0;

            int len;
            int tempSize = 100; //размер временного хранилища
            byte[] bin = new byte[tempSize];    //временное Хранилище для зашифрованной информации
            while (readTotal < inStream.Length)
            {
                len = inStream.Read(bin, 0, tempSize);
                encStream.Write(bin, 0, len);
                readTotal = readTotal + len;
                Console.WriteLine($"{readTotal} байт обработано");
            }
            encStream.Close();
            outStream.Close();
            inStream.Close();
        }

        private static void DecryptFile(string sourceFile, string destFile, byte[] key, byte[] iv)
        {
            using FileStream fileStream = new(sourceFile, FileMode.Open);
            using Aes aes = Aes.Create();

            aes.IV = iv;

            using CryptoStream cryptoStream = new(fileStream,
                                       aes.CreateDecryptor(key, iv),
                                                  CryptoStreamMode.Read); //создаем поток для чтения (расшифровки) данных
            using FileStream outStream = new FileStream(destFile, FileMode.Create);//создаем поток для расшифрованных данных

            using BinaryReader decryptReader = new(cryptoStream);
            int tempSize = 10;  //размер временного хранилища
            byte[] data;        //временное хранилище для зашифрованной информации
            while (true)
            {
                data = decryptReader.ReadBytes(tempSize);
                if (data.Length == 0)
                    break;
                outStream.Write(data, 0, data.Length);
            }
        }

        /*static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            return plaintext;
        }*/
    }
}