using System;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a crypto problem.
    /// <list type="bullet">
    /// <item>
    /// <description><see cref="Dracoon.Crypto.Sdk.InvalidPasswordException"/></description>
    /// <description><see cref="Dracoon.Crypto.Sdk.InvalidKeyPairException"/></description>
    /// <description><see cref="Dracoon.Crypto.Sdk.InvalidFileKeyException"/></description>
    /// <description><see cref="Dracoon.Crypto.Sdk.BadFileException"/></description>
    /// <description><see cref="Dracoon.Crypto.Sdk.CryptoSystemException"/></description>
    /// </item>
    /// </list>
    /// </summary>
    public class CryptoException : Exception {
        public CryptoException() {
        }
        public CryptoException(string message) : base(message) {
        }
        public CryptoException(string message, Exception cause) : base(message, cause) {
        }
    }
}
