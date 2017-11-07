using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the user's key pair.
    /// </summary>
    public class InvalidKeyPairException : CryptoException {
        public InvalidKeyPairException() {
        }
        public InvalidKeyPairException(string message) : base(message) {
        }
        public InvalidKeyPairException(string message, Exception cause) : base(message, cause) {
        }
    }
}
