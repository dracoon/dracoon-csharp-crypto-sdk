using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the password.
    /// </summary>
    public class InvalidPasswordException : CryptoException {
        public InvalidPasswordException() {
        }
        public InvalidPasswordException(string message) : base(message) {
        }
        public InvalidPasswordException(string message, Exception cause) : base(message, cause) {
        }
    }
}
