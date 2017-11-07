using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file key.
    /// </summary>
    public class InvalidFileKeyException : CryptoException {
        public InvalidFileKeyException() {
        }
        public InvalidFileKeyException(string message) : base(message) {
        }
        public InvalidFileKeyException(string message, Exception cause) : base(message, cause) {
        }
    }
}
