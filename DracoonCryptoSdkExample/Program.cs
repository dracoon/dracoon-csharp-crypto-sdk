using Dracoon.Crypto.Sdk.Model;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Dracoon.Crypto.Sdk.Example {
    class Program
    {
        private static readonly String USER_PASSWORD = "acw9q857n(";

        private static readonly String DATA =
                "Things1\n" +
                "OtherThings12\n" +
                "MoreThings123";

        private static readonly int BLOCK_SIZE = 16;

        static void Main(String[] args){
            // --- INITIALIZATION ---
            // Generate key pair
            UserKeyPair userKeyPair = Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA4096, USER_PASSWORD);
            // Check key pair
            if (!Crypto.CheckUserKeyPair(userKeyPair, USER_PASSWORD))
            {
                Trace.WriteLine("Invalid user password!");
                return;
            }

            byte[] plainData = Encoding.UTF8.GetBytes(DATA);

            Trace.WriteLine("Plain Data:");
            Trace.WriteLine(Encoding.UTF8.GetString(plainData));
            Trace.WriteLine("Plain Data: (BASE64)");
            Trace.WriteLine(Convert.ToBase64String(plainData));

            // --- ENCRYPTION ---
            // Generate plain file key
            PlainFileKey fileKey = Crypto.GenerateFileKey(PlainFileKeyAlgorithm.AES256GCM);
            // Encrypt blocks
            byte[] encData = EncryptData(fileKey, plainData);
            // Encrypt file key
            EncryptedFileKey encFileKey = Crypto.EncryptFileKey(fileKey, userKeyPair.UserPublicKey);

            Trace.WriteLine("Encrypted Data: (Base64)");
            Trace.WriteLine(Convert.ToBase64String(encData));

            // --- DECRYPTION ---
            // Decrypt file key
            PlainFileKey decFileKey = Crypto.DecryptFileKey(encFileKey, userKeyPair.UserPrivateKey,
                    USER_PASSWORD);
            // Decrypt blocks
            byte[] decData = DecryptData(decFileKey, encData);

            Trace.WriteLine("Decrypted Data:");
            Trace.WriteLine(Encoding.UTF8.GetString(decData));
            Trace.WriteLine("Decrypted Data: (BASE64)");
            Trace.WriteLine(Convert.ToBase64String(plainData));
        }


        /// <summary>
        /// Encrypts some bytes.
        /// </summary>  
        /// <param name="fileKey">The file key to use.</param>
        ///  <param name="data">The plain bytes.</param>
        /// <returns>Encrypted bytes.</returns>
        private static byte[] EncryptData(PlainFileKey fileKey, byte[] data)
        {

            // !!! This method is an example for encryption. It uses byte array streams for input and
            //     output. However, any kind of stream (e.g. FileInputStream) could be used here.

            FileEncryptionCipher cipher = Crypto.CreateFileEncryptionCipher(fileKey);
            byte[] encData;
            using (Stream is2 = new MemoryStream(data))
            {
                using (MemoryStream os = new MemoryStream())
                {
                    byte[] buffer = new byte[BLOCK_SIZE];
                    int count;
                    try
                    {
                        EncryptedDataContainer eDataContainer;

                        // Encrypt blocks
                        while ((count = is2.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            byte[] pData = createByteArray(buffer, count);
                            eDataContainer = cipher.ProcessBytes(new PlainDataContainer(pData));
                            os.Write(eDataContainer.Content, 0, eDataContainer.Content.Length);
                        }

                        // Complete encryption
                        eDataContainer = cipher.DoFinal();
                        os.Write(eDataContainer.Content, 0, eDataContainer.Content.Length);
                        String tag = Convert.ToBase64String(eDataContainer.Tag);
                        fileKey.Tag = tag;

                        encData = os.ToArray();
                    }
                    catch (IOException e)
                    {
                        throw new Exception("Error while reading/writing data!", e);
                    }
                    catch (CryptoException e)
                    {
                        throw new Exception("Error while encrypting data!", e);
                    }
                }
            }
            return encData;
        }


        /// <summary>
        /// Decrypts some bytes.
        /// </summary>  
        /// <param name="fileKey">The file key to use.</param>
        ///  <param name="data">The encrypted bytes.</param>
        /// <returns>Plain bytes.</returns>
        private static byte[] DecryptData(PlainFileKey fileKey, byte[] data)
        {

            // !!! This method is an example for decryption. Like the method 'encryptData(...)', it uses
            //     byte array streams for input and output. However, any kind of stream
            //     (e.g. FileInputStream) could be used here.

            FileDecryptionCipher cipher = Crypto.CreateFileDecryptionCipher(fileKey);
            byte[] decData;
            using (MemoryStream is2 = new MemoryStream(data))
            {
                using (MemoryStream os = new MemoryStream())
                {
                    byte[] buffer = new byte[BLOCK_SIZE];
                    int count;

                    try
                    {
                        PlainDataContainer pDataContainer;

                        // Decrypt blocks
                        while ((count = is2.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            byte[] eData = createByteArray(buffer, count);
                            pDataContainer = cipher.ProcessBytes(new EncryptedDataContainer(eData, null));
                            os.Write(pDataContainer.Content, 0, pDataContainer.Content.Length);
                        }

                        // Complete decryption
                        byte[] tag = Convert.FromBase64String(fileKey.Tag);
                        pDataContainer = cipher.DoFinal(new EncryptedDataContainer(null, tag));
                        os.Write(pDataContainer.Content, 0, pDataContainer.Content.Length);

                        decData = os.ToArray();
                    }
                    catch (IOException e)
                    {
                        throw new Exception("Error while reading/writing data!", e);
                    }
                    catch (CryptoException e)
                    {
                        throw new Exception("Error while decrypting data!", e);
                    }
                }
            }     
            return decData;
        }

        private static byte[] createByteArray(byte[] bytes, int len)
        {
            byte[] b = new byte[len];
            Array.Copy(bytes, 0, b, 0, len);
            return b;
        }
    }
}
