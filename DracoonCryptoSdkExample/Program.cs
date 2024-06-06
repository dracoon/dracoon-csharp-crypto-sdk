using Dracoon.Crypto.Sdk.Model;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Dracoon.Crypto.Sdk.Example {
    public static class Program {

        private const string UserPassword = "Qwer1234!ä🐛";
        private const string Data = "Things1\nOtherThings12\nMoreThings123";
        private const int BlockSize = 16;

        static void Main(String[] args) {
            // --- INITIALIZATION ---
            char[] userPasswordChars = UserPassword.ToCharArray();

            // Generate key pair
            UserKeyPair userKeyPair = Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA4096, userPasswordChars);

            // Check key pair
            if (!Crypto.CheckUserKeyPair(userKeyPair, userPasswordChars)) {
                Trace.WriteLine("Invalid user password!");
                return;
            }

            byte[] plainData = Encoding.UTF8.GetBytes(Data);

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
                    userPasswordChars);
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
        private static byte[] EncryptData(PlainFileKey fileKey, byte[] data) {

            // !!! This method is an example for encryption. It uses byte array streams for input and
            //     output. However, any kind of stream (e.g. FileInputStream) could be used here.

            FileEncryptionCipher cipher = Crypto.CreateFileEncryptionCipher(fileKey);
            byte[] encData;
            using (Stream is2 = new MemoryStream(data)) {
                using (MemoryStream os = new MemoryStream()) {
                    byte[] buffer = new byte[BlockSize];
                    try {
                        EncryptedDataContainer eDataContainer;

                        // Encrypt blocks
                        int count;
                        while ((count = is2.Read(buffer, 0, buffer.Length)) > 0) {
                            byte[] pData = CreateByteArray(buffer, count);
                            eDataContainer = cipher.ProcessBytes(new PlainDataContainer(pData));
                            os.Write(eDataContainer.Content, 0, eDataContainer.Content.Length);
                        }

                        // Complete encryption
                        eDataContainer = cipher.DoFinal();
                        os.Write(eDataContainer.Content, 0, eDataContainer.Content.Length);
                        string tag = Convert.ToBase64String(eDataContainer.Tag);
                        fileKey.Tag = tag;

                        encData = os.ToArray();
                    } catch (IOException e) {
                        throw new IOException("Error while reading/writing data!", e);
                    } catch (CryptoException e) {
                        throw new CryptoException("Error while encrypting data!", e);
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
        private static byte[] DecryptData(PlainFileKey fileKey, byte[] data) {

            // !!! This method is an example for decryption. Like the method 'encryptData(...)', it uses
            //     byte array streams for input and output. However, any kind of stream
            //     (e.g. FileInputStream) could be used here.

            FileDecryptionCipher cipher = Crypto.CreateFileDecryptionCipher(fileKey);
            byte[] decData;
            using (MemoryStream is2 = new MemoryStream(data)) {
                using (MemoryStream os = new MemoryStream()) {
                    byte[] buffer = new byte[BlockSize];

                    try {
                        PlainDataContainer pDataContainer;

                        // Decrypt blocks
                        int count;
                        while ((count = is2.Read(buffer, 0, buffer.Length)) > 0) {
                            byte[] eData = CreateByteArray(buffer, count);
                            pDataContainer = cipher.ProcessBytes(new EncryptedDataContainer(eData, null));
                            os.Write(pDataContainer.Content, 0, pDataContainer.Content.Length);
                        }

                        // Complete decryption
                        byte[] tag = Convert.FromBase64String(fileKey.Tag);
                        pDataContainer = cipher.DoFinal(new EncryptedDataContainer(null, tag));
                        os.Write(pDataContainer.Content, 0, pDataContainer.Content.Length);

                        decData = os.ToArray();
                    } catch (IOException e) {
                        throw new IOException("Error while reading/writing data!", e);
                    } catch (CryptoException e) {
                        throw new CryptoException("Error while decrypting data!", e);
                    }
                }
            }
            return decData;
        }

        private static byte[] CreateByteArray(byte[] bytes, int len) {
            byte[] b = new byte[len];
            Array.Copy(bytes, 0, b, 0, len);
            return b;
        }
    }
}

