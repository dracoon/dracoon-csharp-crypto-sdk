using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Dracoon.Crypto.Sdk.Model;
using System;
using System.IO;

namespace Dracoon.Crypto.Sdk {
    public class FileCipher {

        // byte
        protected const int blockSize = 16;
        // byte
        protected const int tagSize = 16;

        protected GcmBlockCipher realCipher;
        protected FileCipher(bool forEncryption, PlainFileKey fileKey) {
            try {
                byte[] key = Convert.FromBase64String(fileKey.Key);
                byte[] iv = Convert.FromBase64String(fileKey.Iv);
                AeadParameters parameters = new AeadParameters(new KeyParameter(key), 8 * tagSize, iv);
                realCipher = new GcmBlockCipher(new AesFastEngine());
                realCipher.Init(forEncryption, parameters);
            } catch (Exception e) {
                throw new CryptoSystemException("Could not create " + (forEncryption ? "encryption" : "decryption") + " ciper.", e);
            }
        }

        protected byte[] Process(byte[] block, bool finalize) {
            try {
                using (MemoryStream inputStream = new MemoryStream(block)) {
                    using (MemoryStream outputStream = new MemoryStream()) {
                        byte[] buffer = new byte[blockSize];
                        byte[] processedbuffer = new byte[tagSize + blockSize];
                        int bytesRead, bytesProcessed;
                        while ((bytesRead = inputStream.Read(buffer, 0, blockSize)) != 0) {
                            bytesProcessed = realCipher.ProcessBytes(buffer, 0, bytesRead, processedbuffer, 0);
                            outputStream.Write(processedbuffer, 0, bytesProcessed);
                        }
                        if (finalize) {
                            bytesProcessed = realCipher.DoFinal(processedbuffer, 0);
                            outputStream.Write(processedbuffer, 0, bytesProcessed);
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
