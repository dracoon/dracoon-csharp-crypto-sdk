namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents a private key of a user.
    /// </summary>
    public class UserPrivateKey {

        /// <summary>
        /// The algorithm which is used to create the key.
        /// </summary>
        public UserKeyPairAlgorithm Version { get; set; }

        /// <summary>
        /// The private key string.
        /// </summary>
        public string PrivateKey { get; set; }
    }
}
