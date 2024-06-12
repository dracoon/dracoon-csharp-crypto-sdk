using Dracoon.Crypto.Sdk.Model;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Base class to implement base things for encryption and decryption cipher.
    /// <seealso cref="FileDecryptionCipher"/>
    /// <seealso cref="FileEncryptionCipher"/>
    /// </summary>
    public class FileCipher {

        // byte
        private protected const int BlockSize = 16;
        // byte
        private protected const int TagSize = 16;

        private protected GcmBlockCipher Cipher;

        private protected FileCipher(bool forEncryption, PlainFileKey fileKey) {
            try {
                byte[] key = Convert.FromBase64CharArray(fileKey.Key, 0, fileKey.Key.Length);
                byte[] iv = Convert.FromBase64String(fileKey.Iv);
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), 8 * TagSize, iv);
                Cipher = new GcmBlockCipher(new AesEngine());
                Cipher.Init(forEncryption, parameters);
            } catch (Exception e) {
                throw new CryptoSystemException("Could not create " + (forEncryption ? "encryption" : "decryption") + " cipher.", e);
            }
        }

        private protected byte[] Process(byte[] block, bool finalize) {
            try {
                using (MemoryStream inputStream = new MemoryStream(block)) {
                    using (MemoryStream outputStream = new MemoryStream()) {
                        byte[] buffer = new byte[BlockSize];
                        byte[] processedBuffer = new byte[TagSize + BlockSize];
                        int bytesRead, bytesProcessed;
                        while ((bytesRead = inputStream.Read(buffer, 0, BlockSize)) != 0) {
                            bytesProcessed = Cipher.ProcessBytes(buffer, 0, bytesRead, processedBuffer, 0);
                            outputStream.Write(processedBuffer, 0, bytesProcessed);
                        }
                        if (finalize) {
                            bytesProcessed = Cipher.DoFinal(processedBuffer, 0);
                            outputStream.Write(processedBuffer, 0, bytesProcessed);
                        }
                        outputStream.Flush();
                        return outputStream.ToArray();
                    }
                }
            } catch (InvalidCipherTextException e) {
                throw new BadFileException("Could not en/decrypt file. File content is bad.", e);
            } catch (Exception e) {
                throw new CryptoException("Could not decrypt file. Decryption failed.", e);
            }
        }
    }
}
