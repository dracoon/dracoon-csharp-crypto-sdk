using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file.
    /// </summary>
    [Serializable]
    public class BadFileException : CryptoException {

        public BadFileException() { }

        public BadFileException(string message) : base(message) { }

        public BadFileException(string message, Exception cause) : base(message, cause) { }

        protected BadFileException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
