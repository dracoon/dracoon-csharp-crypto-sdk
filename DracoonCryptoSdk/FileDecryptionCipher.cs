using Dracoon.Crypto.Sdk.Model;
using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Implements the DRACOON file decryption.
    /// </summary>
    public class FileDecryptionCipher : FileCipher {

        internal FileDecryptionCipher(PlainFileKey fileKey) : base(false, fileKey) {
        }

        /// <summary>
        /// Decrypts some bytes.
        /// </summary>
        /// <param name="encryptedData">The data container with the bytes to decrypt.</param>
        /// <returns>The data container with the decrypted bytes.</returns>
        /// <exception cref="CryptoException"/>
        /// <exception cref="BadFileException"/>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentException"/>
        public PlainDataContainer ProcessBytes(EncryptedDataContainer encryptedData) {
            if (encryptedData == null) {
                throw new ArgumentNullException(nameof(encryptedData), "Data container cannot be null.");
            }
            if (encryptedData.Content == null) {
                throw new ArgumentNullException(nameof(encryptedData), "Data container content cannot be null.");
            }
            if (encryptedData.Tag != null) {
                throw new ArgumentException($"{nameof(encryptedData.Tag)} must be null.");
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
        /// <exception cref="CryptoException"/>
        /// <exception cref="BadFileException"/>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentException"/>
        public PlainDataContainer DoFinal(EncryptedDataContainer encryptedData) {
            if (encryptedData == null) {
                throw new ArgumentNullException(nameof(encryptedData), "Data container cannot be null.");
            }
            if (encryptedData.Content != null) {
                throw new ArgumentException($"{nameof(encryptedData.Content)} must be null.");
            }
            if (encryptedData.Tag == null) {
                throw new ArgumentNullException(nameof(encryptedData), "Data container tag must be null.");
            }
            return new PlainDataContainer(Process(encryptedData.Tag, true));
        }
    }
}
