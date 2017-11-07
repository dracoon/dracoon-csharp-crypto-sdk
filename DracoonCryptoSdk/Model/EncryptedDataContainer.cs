namespace Dracoon.Crypto.Sdk.Model {
    public class EncryptedDataContainer {
        public byte[] Content {
            get; private set;
        }
        public byte[] Tag {
            get; private set;
        }
        /// <summary>
        /// Creates a encryted data container.
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
