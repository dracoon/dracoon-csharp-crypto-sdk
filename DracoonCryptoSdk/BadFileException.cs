using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file.
    /// </summary>
    [Serializable]
    public class BadFileException : CryptoException {

        /// <inheritdoc/>
        public BadFileException() { }

        /// <inheritdoc/>
        public BadFileException(string message) : base(message) { }

        /// <inheritdoc/>
        public BadFileException(string message, Exception cause) : base(message, cause) { }

        /// <inheritdoc/>
        protected BadFileException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
