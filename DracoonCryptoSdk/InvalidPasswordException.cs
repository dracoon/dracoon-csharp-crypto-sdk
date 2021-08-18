using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the password.
    /// </summary>
    [Serializable]
    public class InvalidPasswordException : CryptoException {

        /// <inheritdoc/>
        public InvalidPasswordException() { }

        /// <inheritdoc/>
        public InvalidPasswordException(string message) : base(message) { }

        /// <inheritdoc/>
        public InvalidPasswordException(string message, Exception cause) : base(message, cause) { }

        /// <inheritdoc/>
        protected InvalidPasswordException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
