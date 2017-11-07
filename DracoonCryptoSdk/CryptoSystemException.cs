using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals that an unexpected crypto error occurred. (Mostly missing algorithms, unsuppoerted padding, ...)
    /// </summary>
    public class CryptoSystemException : CryptoException {
        public CryptoSystemException() {
        }
        public CryptoSystemException(string message) : base(message) {
        }
        public CryptoSystemException(string message, Exception cause) : base(message, cause) {
        }
    }
}
