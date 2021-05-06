using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the user's key pair.
    /// </summary>
    [Serializable]
    public class InvalidKeyPairException : CryptoException {

        /// <inheritdoc/>
        public InvalidKeyPairException() { }

        /// <inheritdoc/>
        public InvalidKeyPairException(string message) : base(message) { }

        /// <inheritdoc/>
        public InvalidKeyPairException(string message, Exception cause) : base(message, cause) { }

        /// <inheritdoc/>
        protected InvalidKeyPairException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
