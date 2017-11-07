using Dracoon.Crypto.Sdk.Model;
using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Implements the Secure Data Space file decryption.
    /// </summary>
    public class FileDecryptionCipher : FileCipher {

        internal FileDecryptionCipher(PlainFileKey fileKey) : base(false, fileKey) {
        }
        /// <summary>
        /// Decrypts some bytes.
        /// </summary>
        /// <param name="encryptedData">The data container with the bytes to decrypt.</param>
        /// <returns>The data container with the decrypted bytes.</returns>
        /// <exception cref="Dracoon.Crypto.Sdk.CryptoException"/>
        /// <exception cref="Dracoon.Crypto.Sdk.BadFileException"/>
        /// <exception cref="System.ArgumentNullException"/>
        /// <exception cref="System.ArgumentException"/>
        public PlainDataContainer ProcessBytes(EncryptedDataContainer encryptedData) {
            if (encryptedData == null) {
                throw new ArgumentNullException("Data container cannot be null.");
            }
            if (encryptedData.Content == null) {
                throw new ArgumentNullException("Data container content cannot be null.");
            }
            if (encryptedData.Tag != null) {
                throw new ArgumentException("Data container tag must be null.");
            }
            return new PlainDataContainer(Process(encryptedData.Content, false));
        }

        /// <summary>
        /// Completes the decryption. After this method is called no further calls of 
        /// <see cref="ProcessBytes(EncryptedDataContainer)"/> and
        /// <see cref="DoFinal(EncryptedDataContainer)"/> are possible.
        /// </summary>
        /// <param name="encryptedData">The data container with the previously calculated tag.</param>
        /// <returns>The data container with the decrypted bytes.</returns>
        /// <exception cref="Dracoon.Crypto.Sdk.CryptoException"/>
        /// <exception cref="Dracoon.Crypto.Sdk.BadFileException"/>
        /// <exception cref="System.ArgumentNullException"/>
        /// <exception cref="System.ArgumentException"/>
        public PlainDataContainer DoFinal(EncryptedDataContainer encryptedData) {
            if (encryptedData == null) {
                throw new ArgumentNullException("Data container cannot be null.");
            }
            if (encryptedData.Content != null) {
                throw new ArgumentException("Data container content cannot be null.");
            }
            if (encryptedData.Tag == null) {
                throw new ArgumentNullException("Data container tag must be null.");
            }
            return new PlainDataContainer(Process(encryptedData.Tag, true));
        }
    }
}
