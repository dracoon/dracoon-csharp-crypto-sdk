namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents a public key of a user.
    /// </summary>
    public class UserPublicKey {

        /// <summary>
        /// The algorithm which is used to create the key.
        /// </summary>
        public UserKeyPairAlgorithm Version { get; set; }

        /// <summary>
        /// The public key string.
        /// </summary>
        public string PublicKey { get; set; }
    }
}
