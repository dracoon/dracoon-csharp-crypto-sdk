using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file key.
    /// </summary>
    [Serializable]
    public class InvalidFileKeyException : CryptoException {

        public InvalidFileKeyException() { }

        public InvalidFileKeyException(string message) : base(message) { }

        public InvalidFileKeyException(string message, Exception cause) : base(message, cause) { }

        protected InvalidFileKeyException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
