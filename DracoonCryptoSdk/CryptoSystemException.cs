using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals that an unexpected crypto error occurred. (Mostly missing algorithms, unsupported padding, ...)
    /// </summary>
    [Serializable]
    public class CryptoSystemException : CryptoException {

        /// <inheritdoc/>
        public CryptoSystemException() { }

        /// <inheritdoc/>
        public CryptoSystemException(string message) : base(message) { }

        /// <inheritdoc/>
        public CryptoSystemException(string message, Exception cause) : base(message, cause) { }

        /// <inheritdoc/>
        protected CryptoSystemException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
