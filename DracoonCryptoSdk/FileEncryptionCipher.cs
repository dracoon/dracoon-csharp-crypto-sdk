using Dracoon.Crypto.Sdk.Model;
using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Implements the DRACOON file encryption.
    /// </summary>
    public class FileEncryptionCipher : FileCipher {

        internal FileEncryptionCipher(PlainFileKey fileKey) : base(true, fileKey) {
        }

        /// <summary>
        /// Encrypts some bytes.
        /// </summary>
        /// <param name="plainData">The data container with the bytes to encrypt.</param>
        /// <returns>The data container with the encrypted bytes.</returns>
        /// <exception cref="CryptoException"/>
        /// <exception cref="BadFileException"/>
        /// <exception cref="ArgumentNullException"/>
        public EncryptedDataContainer ProcessBytes(PlainDataContainer plainData) {
            if (plainData == null) {
                throw new ArgumentNullException(nameof(plainData), "Data container cannot be null.");
            }
            if (plainData.Content == null) {
                throw new ArgumentNullException(nameof(plainData), "Data container content cannot be null.");
            }
            return new EncryptedDataContainer(Process(plainData.Content, false), null);
        }

        /// <summary>
        /// Completes the encryption. After this method is called no further calls of
        /// <see cref="ProcessBytes(PlainDataContainer)"/> and
        /// <see cref="DoFinal()"/> are possible.
        /// </summary>
        /// <returns>The data container with the encrypted bytes and the calculated tag.</returns>
        /// <exception cref="CryptoException"/>
        /// <exception cref="BadFileException"/>
        public EncryptedDataContainer DoFinal() {
            byte[] resultData = Process(new byte[] { }, true);
            byte[] contentBytes = new byte[resultData.Length - TagSize];
            byte[] tagBytes = new byte[TagSize];
            Array.Copy(resultData, 0, contentBytes, 0, contentBytes.Length);
            Array.Copy(resultData, contentBytes.Length, tagBytes, 0, tagBytes.Length);
            return new EncryptedDataContainer(contentBytes, tagBytes);
        }
    }
}
