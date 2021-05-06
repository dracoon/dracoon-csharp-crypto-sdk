namespace Dracoon.Crypto.Sdk.Model {
    /// <summary>
    /// Represents a key pair of a user.
    /// </summary>
    public class UserKeyPair {

        /// <summary>
        /// The private key of a user.
        /// </summary>

        public UserPrivateKey UserPrivateKey { get; set; }

        /// <summary>
        /// The public key of a user.
        /// </summary>
        public UserPublicKey UserPublicKey { get; set; }
    }
}
