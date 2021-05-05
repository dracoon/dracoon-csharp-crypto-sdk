using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the password.
    /// </summary>
    [Serializable]
    public class InvalidPasswordException : CryptoException {

        public InvalidPasswordException() { }

        public InvalidPasswordException(string message) : base(message) { }

        public InvalidPasswordException(string message, Exception cause) : base(message, cause) { }

        protected InvalidPasswordException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
