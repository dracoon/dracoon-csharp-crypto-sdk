namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents a plain block for the encryption.
    /// </summary>
    public class PlainDataContainer {

        /// <summary>
        /// Plain bytes.
        /// </summary>
        public byte[] Content { get; }

        /// <summary>
        /// Creates a plain data container.
        /// </summary>
        /// <param name="content">The content bytes of this block.</param>
        public PlainDataContainer(byte[] content) {
            Content = content;
        }
    }
}
