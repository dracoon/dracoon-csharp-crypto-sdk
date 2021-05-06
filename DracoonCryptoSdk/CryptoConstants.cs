using System;
using System.Reflection;

namespace Dracoon.Crypto.Sdk {

    /// <summary>
    /// The asymmetric algorithms which are currently available to create a user key pair.
    /// </summary>
    public enum UserKeyPairAlgorithm {
        /// <summary>
        /// The algorithm RSA with key length of 2048 bit.
        /// </summary>
        [StringValue("A")]
        RSA2048 = 1,
        /// <summary>
        /// The algorithm RSA with key length of 4096 bit.
        /// </summary>
        [StringValue("RSA-4096")]
        RSA4096 = 2
    }

    /// <summary>
    /// The algorithms combination which are currently available to encrypt a symmetric file key with a asymmetric user key pair.
    /// </summary>
    public enum EncryptedFileKeyAlgorithm {
        /// <summary>
        /// The algorithm RSA with key length of 2048 bit in combination with AES 256 bit (GCM).
        /// </summary>
        [StringValue("A")]
        RSA2048_AES256GCM = 1,
        /// <summary>
        /// The algorithm RSA with key length of 4096 bit in combination with AES 256 bit (GCM).
        /// </summary>
        [StringValue("RSA-4096/AES-256-GCM")]
        RSA4096_AES256GCM = 2
    }

    /// <summary>
    /// The symmetric algorithms which are currently available to encrypt file keys.
    /// </summary>
    public enum PlainFileKeyAlgorithm {
        /// <summary>
        /// The algorithm AES 256 bit (GCM).
        /// </summary>
        [StringValue("A")]
        AES256GCM = 1
    }

    internal class StringValueAttribute : Attribute {
        public string StringValue { get; protected set; }

        public StringValueAttribute(string value) {
            StringValue = value;
        }
    }

    /// <summary>
    /// Extensions for user key pair algorithm enum.
    /// </summary>
    public static class EnumExtensionUserKeyPairAlgorithm {

        /// <summary>
        /// Extension to cast a user key pair algorithm enum into the corresponding string value.
        /// </summary>
        /// <param name="value">The user key pair algorithm enum.</param>
        /// <returns>The corresponding string value of the user key pair algorithm enum.</returns>
        public static string GetStringValue(this UserKeyPairAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            return (fieldInfo.GetCustomAttributes(
                        typeof(StringValueAttribute), false) is StringValueAttribute[] attributes && attributes.Length > 0) ? attributes[0].StringValue : null;
        }

        /// <summary>
        /// Extension to cast a string value into the corresponding enum.
        /// </summary>
        /// <param name="algorithm">Indicator for the extension.</param>
        /// <param name="value">The user key pair algorithm string.</param>
        /// <returns>The corresponding enum of the user key pair algorithm string.</returns>
        /// <exception cref="InvalidFileKeyException">Thrown when no enum exists for the given string value.</exception>
        public static UserKeyPairAlgorithm ParseAlgorithm(this UserKeyPairAlgorithm algorithm, string value) {
            switch (value) {
                case "A":
                    return UserKeyPairAlgorithm.RSA2048;
                case "RSA-4096":
                    return UserKeyPairAlgorithm.RSA4096;
                default:
                    throw new InvalidKeyPairException((value ?? "null") + " is not a supported key pair algorithm.");
            }
        }
    }

    /// <summary>
    /// Extensions for encrypted file key algorithm enum.
    /// </summary>
    public static class EnumExtensionEncryptedFileKeyAlgorithm {

        /// <summary>
        /// Extension to cast a encrypted file key algorithm enum into the corresponding string value.
        /// </summary>
        /// <param name="value">The encrypted file key algorithm enum.</param>
        /// <returns>The corresponding string value of the encrypted file key algorithm enum.</returns>
        public static string GetStringValue(this EncryptedFileKeyAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            return (fieldInfo.GetCustomAttributes(
                        typeof(StringValueAttribute), false) is StringValueAttribute[] attributes && attributes.Length > 0) ? attributes[0].StringValue : null;
        }


        /// <summary>
        /// Extension to cast a string value into the corresponding enum.
        /// </summary>
        /// <param name="algorithm">Indicator for the extension.</param>
        /// <param name="value">The encrypted file key algorithm string.</param>
        /// <returns>The corresponding enum of the encrypted file key algorithm string.</returns>
        /// <exception cref="InvalidFileKeyException">Thrown when no enum exists for the given string value.</exception>
        public static EncryptedFileKeyAlgorithm ParseAlgorithm(this EncryptedFileKeyAlgorithm algorithm, string value) {
            switch (value) {
                case "A":
                    return EncryptedFileKeyAlgorithm.RSA2048_AES256GCM;
                case "RSA-4096/AES-256-GCM":
                    return EncryptedFileKeyAlgorithm.RSA4096_AES256GCM;
                default:
                    throw new InvalidFileKeyException((value ?? "null") + " is not a supported encrypted file key algorithm.");
            }
        }

        /// <summary>
        /// Extension to get the plain file key algorithm for a given encrypted file key algorithm.
        /// </summary>
        /// <param name="algorithm">The encrypted file key algorithm enum.</param>
        /// <returns>The corresponding plain file key algorithm enum.</returns>
        /// <exception cref="InvalidFileKeyException">Thrown when no corresponding plain file key algorithm enum exists for the given encrypted file key algorithm enum.</exception>
        internal static PlainFileKeyAlgorithm ParseEncryptedAlgorithm(this EncryptedFileKeyAlgorithm algorithm) {
            switch (algorithm) {
                case EncryptedFileKeyAlgorithm.RSA2048_AES256GCM:
                    return PlainFileKeyAlgorithm.AES256GCM;
                case EncryptedFileKeyAlgorithm.RSA4096_AES256GCM:
                    return PlainFileKeyAlgorithm.AES256GCM;
                default:
                    throw new InvalidFileKeyException("Cannot parse " + algorithm.GetStringValue() + " to plain file key algorithm.");
            }
        }
    }

    /// <summary>
    /// Extensions for plain file key algorithm enum.
    /// </summary>
    public static class EnumExtensionPlainFileKeyAlgorithm {

        /// <summary>
        /// Extension to cast a plain file key algorithm enum into the corresponding string value.
        /// </summary>
        /// <param name="value">The plain file key algorithm enum.</param>
        /// <returns>The corresponding string value of the plain file key algorithm enum.</returns>
        public static string GetStringValue(this PlainFileKeyAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            return (fieldInfo.GetCustomAttributes(
                        typeof(StringValueAttribute), false) is StringValueAttribute[] attributes && attributes.Length > 0) ? attributes[0].StringValue : null;
        }

        /// <summary>
        /// Extension to cast a string value into the corresponding enum.
        /// </summary>
        /// <param name="algorithm">Indicator for the extension.</param>
        /// <param name="value">The plain file key algorithm string.</param>
        /// <returns>The corresponding enum of the plain file key algorithm string.</returns>
        /// <exception cref="InvalidFileKeyException">Thrown when no enum exists for the given string value.</exception>
        public static PlainFileKeyAlgorithm ParseAlgorithm(this PlainFileKeyAlgorithm algorithm, string value) {
            switch (value) {
                case "A":
                    return PlainFileKeyAlgorithm.AES256GCM;
                default:
                    throw new InvalidFileKeyException((value ?? "null") + " is not a supported plain file key algorithm.");
            }
        }

        /// <summary>
        /// Extension to get the encrypted file key algorithm enum for a given combination of plain file key algorithm and user key pair algorithm.
        /// </summary>
        /// <param name="algorithm">The plain file key algorithm enum.</param>
        /// <param name="keyPairAlgorithm">The user key pair algorithm enum.</param>
        /// <returns>The encrypted file key algorithm enum in relation to the two given algorithms.</returns>
        /// <exception cref="InvalidFileKeyException">Thrown when no combination of the two given algorithms are possible.</exception>
        internal static EncryptedFileKeyAlgorithm ParsePlainFileKeyAlgorithm(this PlainFileKeyAlgorithm algorithm, UserKeyPairAlgorithm keyPairAlgorithm) {
            switch (algorithm) {
                case PlainFileKeyAlgorithm.AES256GCM:
                    switch (keyPairAlgorithm) {
                        case UserKeyPairAlgorithm.RSA4096:
                            return EncryptedFileKeyAlgorithm.RSA4096_AES256GCM;
                        default:
                            return EncryptedFileKeyAlgorithm.RSA2048_AES256GCM;
                    }
                default:
                    throw new InvalidFileKeyException("Cannot parse " + algorithm.GetStringValue() + " to plain file key algorithm.");
            }
        }
    }

}
