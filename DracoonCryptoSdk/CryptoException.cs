using System;
using System.Runtime.Serialization;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// Signals a crypto problem.
    /// <list type="bullet">
    /// <item>
    /// <description><see cref="InvalidPasswordException"/></description>
    /// <description><see cref="InvalidKeyPairException"/></description>
    /// <description><see cref="InvalidFileKeyException"/></description>
    /// <description><see cref="BadFileException"/></description>
    /// <description><see cref="CryptoSystemException"/></description>
    /// </item>
    /// </list>
    /// </summary>
    [Serializable]
    public class CryptoException : Exception {

        public CryptoException() { }

        public CryptoException(string message) : base(message) { }

        public CryptoException(string message, Exception cause) : base(message, cause) { }

        protected CryptoException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
