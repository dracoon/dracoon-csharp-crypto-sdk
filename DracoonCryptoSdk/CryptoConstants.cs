using System;
using System.Reflection;

namespace Dracoon.Crypto.Sdk {

    public enum UserKeyPairAlgorithm : int {
        [StringValue("A")]
        RSA2048 = 1,
        [StringValue("RSA-4096")]
        RSA4096 = 2
    }

    public enum EncryptedFileKeyAlgorithm : int {
        [StringValue("A")]
        RSA2048_AES256GCM = 1,
        [StringValue("RSA-4096/AES-256-GCM")]
        RSA4096_AES256GCM = 2
    }

    public enum PlainFileKeyAlgorithm : int {
        [StringValue("A")]
        AES256GCM = 1
    }

    internal class StringValueAttribute : Attribute {
        public string StringValue { get; protected set; }

        public StringValueAttribute(string value) {
            StringValue = value;
        }
    }

    public static class EnumExtension_UserKeyPairAlgorithm {
        public static string GetStringValue(this UserKeyPairAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            StringValueAttribute[] attribs = fieldInfo.GetCustomAttributes(
                typeof(StringValueAttribute), false) as StringValueAttribute[];

            return attribs.Length > 0 ? attribs[0].StringValue : null;
        }

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

    public static class EnumExtension_EncryptedFileKeyAlgorithm {

        public static string GetStringValue(this EncryptedFileKeyAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            StringValueAttribute[] attribs = fieldInfo.GetCustomAttributes(
                typeof(StringValueAttribute), false) as StringValueAttribute[];

            return attribs.Length > 0 ? attribs[0].StringValue : null;
        }

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

    public static class EnumExtension_PlainFileKeyAlgorithm {
        public static string GetStringValue(this PlainFileKeyAlgorithm value) {
            Type type = value.GetType();

            FieldInfo fieldInfo = type.GetField(value.ToString());

            StringValueAttribute[] attribs = fieldInfo.GetCustomAttributes(
                typeof(StringValueAttribute), false) as StringValueAttribute[];

            return attribs.Length > 0 ? attribs[0].StringValue : null;
        }

        public static PlainFileKeyAlgorithm ParseAlgorithm(this PlainFileKeyAlgorithm algorithm, string value) {
            switch (value) {
                case "A":
                    return PlainFileKeyAlgorithm.AES256GCM;
                default:
                    throw new InvalidFileKeyException((value ?? "null") + " is not a supported plain file key algorithm.");
            }
        }

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
