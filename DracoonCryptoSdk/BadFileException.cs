using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a problem with the file.
    /// </summary>
    public class BadFileException : CryptoException {
        public BadFileException() {
        }
        public BadFileException(string message) : base(message) {
        }
        public BadFileException(string message, Exception cause) : base(message, cause) {
        }
    }
}
