using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file key.
    /// </summary>
    [Serializable]
    public class InvalidFileKeyException : CryptoException {

        /// <inheritdoc/>
        public InvalidFileKeyException() { }

        /// <inheritdoc/>
        public InvalidFileKeyException(string message) : base(message) { }

        /// <inheritdoc/>
        public InvalidFileKeyException(string message, Exception cause) : base(message, cause) { }

        /// <inheritdoc/>
        protected InvalidFileKeyException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
