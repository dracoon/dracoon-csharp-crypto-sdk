using Dracoon.Crypto.Sdk.Model;
using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Implements the Secure Data Space file encryption.
    /// </summary>
    public class FileEncryptionCipher : FileCipher {
        internal FileEncryptionCipher(PlainFileKey fileKey) : base(true, fileKey) {
        }
        /// <summary>
        /// Encrypts some bytes.
        /// </summary>
        /// <param name="plainData">The data container with the bytes to encrypt.</param>
        /// <returns>The data container with the encrypted bytes.</returns>
        /// <exception cref="Dracoon.Crypto.Sdk.CryptoException"/>
        /// <exception cref="Dracoon.Crypto.Sdk.BadFileException"/>
        /// <exception cref="System.ArgumentNullException"/>
        public EncryptedDataContainer ProcessBytes(PlainDataContainer plainData) {
            if (plainData == null) {
                throw new ArgumentNullException("Data container cannot be null.");
            }
            if (plainData.Content == null) {
                throw new ArgumentNullException("Data container content cannot be null.");
            }
            return new EncryptedDataContainer(Process(plainData.Content, false), null);
        }
        /// <summary>
        /// Completes the encryption. After this method is called no further calls of
        /// <see cref="ProcessBytes(PlainDataContainer)"/> and
        /// <see cref="DoFinal()"/> are possible.
        /// </summary>
        /// <returns>The data container with the encrypted bytes and the calculated tag.</returns>
        /// <exception cref="Dracoon.Crypto.Sdk.CryptoException"/>
        /// <exception cref="Dracoon.Crypto.Sdk.BadFileException"/>
        public EncryptedDataContainer DoFinal() {
            byte[] resultData = Process(new byte[] { }, true);
            byte[] contentBytes = new byte[resultData.Length - tagSize];
            byte[] tagBytes = new byte[tagSize];
            Array.Copy(resultData, 0, contentBytes, 0, contentBytes.Length);
            Array.Copy(resultData, contentBytes.Length, tagBytes, 0, tagBytes.Length);
            return new EncryptedDataContainer(contentBytes, tagBytes);
        }
    }
}
