namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents an plain file key.
    /// </summary>
    public class PlainFileKey {

        /// <summary>
        /// The plain file key (chars) as base64 byte array.
        /// </summary>
        public char[] Key { get; set; }

        /// <summary>
        /// The initialization vector which is used on the key encryption.
        /// </summary>
        public string Iv { get; set; }

        /// <summary>
        /// The tag which is used on the key encryption.
        /// </summary>
        public string Tag { get; set; }

        /// <summary>
        /// The algorithm which is used to encrypt the file key.
        /// </summary>
        public PlainFileKeyAlgorithm Version { get; set; }
    }
}
