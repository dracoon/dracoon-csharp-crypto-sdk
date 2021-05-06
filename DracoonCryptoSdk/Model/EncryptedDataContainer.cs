namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents an encrypted block for the decryption.
    /// </summary>
    public class EncryptedDataContainer {
        
        /// <summary>
        /// The encrypted content bytes.
        /// </summary>
        public byte[] Content { get; }

        /// <summary>
        /// The tag bytes.
        /// </summary>
        public byte[] Tag { get; }

        /// <summary>
        /// Creates a encrypted data container.
        /// </summary>
        /// <param name="content">If you want use this container for <see cref="FileDecryptionCipher.ProcessBytes(EncryptedDataContainer)"/> you must set this bytes. 
        /// Otherwise null.
        /// </param>
        /// <param name="tag">If you want use this container for <see cref="FileDecryptionCipher.DoFinal(EncryptedDataContainer)"/> you must set this bytes. 
        /// Otherwise null.
        /// </param>
        public EncryptedDataContainer(byte[] content, byte[] tag) {
            Content = content;
            Tag = tag;
        }
    }
}
