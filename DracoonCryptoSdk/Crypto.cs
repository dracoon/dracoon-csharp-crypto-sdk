using Dracoon.Crypto.Sdk.Model;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// <para>This class is the main class of the Secure Data Space Crypto Library.</para>
    /// <para/>
    /// The class provides methods for:
    /// <list type="bullet">
    /// 
    /// <item>
    /// <description>User key pair generation: 
    /// <see cref="Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm, char[])"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description>User key pair check: 
    /// <see cref="Crypto.CheckUserKeyPair(UserKeyPair, char[])"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description> File key generation: 
    /// <see cref="Crypto.GenerateFileKey(PlainFileKeyAlgorithm)"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description> File key encryption:
    /// <see cref="Crypto.EncryptFileKey(PlainFileKey, UserPublicKey)"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description> File key decryption:
    /// <see cref="Crypto.DecryptFileKey(EncryptedFileKey, UserPrivateKey, char[])"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description> Cipher creation for file encryption:
    /// <see cref="Crypto.CreateFileEncryptionCipher(PlainFileKey)"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description> Cipher creation for file decryption:
    /// <see cref="Crypto.CreateFileDecryptionCipher(PlainFileKey)"/>
    /// </description>
    /// </item>
    /// </list>
    /// </summary>
    public class Crypto {

        private class Password : IPasswordFinder {

            private readonly char[] _password;

            public Password(char[] word) {
                _password = (char[]) word.Clone();
            }

            public char[] GetPassword() {
                return (char[]) _password.Clone();
            }

            public void ClearPasswordArray() {
                Array.Clear(_password, 0, _password.Length);
            }
        }

        private const int pbkdf2HashIterationCount = 1300000;
        private const int pbkdf2SaltSize = 20;
        private const int IvSize = 12;

        private static AsymmetricCipherKeyPair ParseAsymmetricCipherKeyPair(UserKeyPairAlgorithm algorithm) {
            AsymmetricCipherKeyPair asymmetricCipher;
            try {
                RsaKeyPairGenerator gen = new RsaKeyPairGenerator();
                switch (algorithm) {
                    case UserKeyPairAlgorithm.RSA2048:
                        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
                        break;
                    case UserKeyPairAlgorithm.RSA4096:
                        gen.Init(new KeyGenerationParameters(new SecureRandom(), 4096));
                        break;
                    default:
                        throw new InvalidKeyPairException((algorithm.GetStringValue() ?? "null") + " is not a supported key pair algorithm.");
                }
                asymmetricCipher = gen.GenerateKeyPair();
            } catch (CryptographicException e) {
                throw new CryptoSystemException("Could not generate RSA key pair.", e);
            }
            return asymmetricCipher;
        }

        private static int ParseSymmetricKeyLength(PlainFileKeyAlgorithm algorithm) {
            switch (algorithm) {
                case PlainFileKeyAlgorithm.AES256GCM:
                    return 32;
                default:
                    throw new InvalidFileKeyException((algorithm.GetStringValue() ?? "null") + " is not a supported file key algorithm.");
            }
        }

        #region Key management

        /// <summary>
        /// Generates a random user key pair.
        /// </summary>
        /// <param name="algorithm">The encryption algorithm for which the key pair should be created.</param>
        /// <param name="password">The password which should be used to secure the private key.</param>
        /// <returns>The generated user key pair.</returns>
        /// <exception cref="InvalidKeyPairException">If the version for the user key pair is not supported.</exception>
        /// <exception cref="InvalidPasswordException">If the password to secure the private key is invalid.</exception>
        /// <exception cref="CryptoSystemException">If an unexpected error occured.</exception>
        /// <exception cref="CryptoException">If an unexpected error in the encryption of the private key occured.</exception>
        public static UserKeyPair GenerateUserKeyPair(UserKeyPairAlgorithm algorithm, char[] password) {
            ValidatePassword(password);

            AsymmetricCipherKeyPair rsaKeyInfo = ParseAsymmetricCipherKeyPair(algorithm);

            string encryptedPrivateKeyString = EncryptPrivateKey(rsaKeyInfo.Private, password);
            string publicKeyString = ConvertPublicKey(rsaKeyInfo.Public);

            UserPrivateKey userPrivateKey = new UserPrivateKey() { Version = algorithm, PrivateKey = encryptedPrivateKeyString };
            UserPublicKey userPublicKey = new UserPublicKey() { Version = algorithm, PublicKey = publicKeyString };

            return new UserKeyPair() { UserPrivateKey = userPrivateKey, UserPublicKey = userPublicKey };
        }

        private static string EncryptPrivateKey(AsymmetricKeyParameter privateKey, char[] password) {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            string result = null;

            // Create salts
            byte[] aesIv = new byte[16];
            byte[] keySalt = new byte[pbkdf2SaltSize];
            SecureRandom randomGen = new SecureRandom();
            randomGen.NextBytes(aesIv);
            randomGen.NextBytes(keySalt);
            try {
                PrivateKeyInfo decryptedPrivateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

                // Prepare encryption
                Pkcs5S2ParametersGenerator pkcs5S2Gen = new Pkcs5S2ParametersGenerator(new Sha1Digest());
                pkcs5S2Gen.Init(passwordBytes, keySalt, pbkdf2HashIterationCount);
                ICipherParameters cipherParams = pkcs5S2Gen.GenerateDerivedParameters(NistObjectIdentifiers.IdAes256Cbc.Id, 256);
                IBufferedCipher cipher = CipherUtilities.GetCipher(NistObjectIdentifiers.IdAes256Cbc);
                cipher.Init(true, new ParametersWithIV(cipherParams, aesIv));

                // Generate encrypted private key info
                Asn1OctetString aesIvOctetString = new DerOctetString(aesIv);
                KeyDerivationFunc keyFunction = new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, new Pbkdf2Params(keySalt, pbkdf2HashIterationCount, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha1, DerNull.Instance)));
                EncryptionScheme encScheme = new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, aesIvOctetString);
                Asn1EncodableVector encryptionInfo = new Asn1EncodableVector { keyFunction, encScheme };
                AlgorithmIdentifier algIdentifier = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, new DerSequence(encryptionInfo));
                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(algIdentifier, cipher.DoFinal(decryptedPrivateKeyInfo.GetEncoded()));
                Org.BouncyCastle.Utilities.IO.Pem.PemObject pkPemObject = new Org.BouncyCastle.Utilities.IO.Pem.PemObject("ENCRYPTED PRIVATE KEY", encryptedPrivateKeyInfo.GetEncoded());

                // Write the PEM object to a string
                using (StringWriter sWriter = new StringWriter()) {
                    using (PemWriter pemWriter = new PemWriter(sWriter)) {
                        pemWriter.WriteObject(pkPemObject);
                        pemWriter.Writer.Flush();
                        result = pemWriter.Writer.ToString();
                    }
                }
            } catch (Exception e) {
                throw new CryptoException("Could not encrypt private key.", e);
            } finally {
                Array.Clear(aesIv, 0, aesIv.Length);
                Array.Clear(keySalt, 0, keySalt.Length);
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
            return result;
        }

        private static AsymmetricKeyParameter DecryptPrivateKey(string encryptedPrivateKey, char[] password, string encoding = "utf-8") {
            Environment.SetEnvironmentVariable("Org.BouncyCastle.Asn1.AllowUnsafeInteger", "true", EnvironmentVariableTarget.Process);
            byte[] passwordBytes = Encoding.GetEncoding(encoding).GetBytes(password);
            Password p = new Password(ConvertBytesToChars(passwordBytes));
            Array.Clear(passwordBytes, 0, passwordBytes.Length);
            try {
                AsymmetricKeyParameter decryptedPrivateKey;
                using (StringReader tr = new StringReader(encryptedPrivateKey)) {
                    using (PemReader pemReader = new PemReader(tr, p)) {
                        decryptedPrivateKey = (AsymmetricKeyParameter) pemReader.ReadObject();
                    }
                }
                return decryptedPrivateKey;
            } catch (PemException e) {
                if (e.Message.StartsWith("problem creating ENCRYPTED private key: Org.BouncyCastle.Crypto.InvalidCipherTextException")) {
                    if(encoding == "utf-8") {
                        // default encoding is utf-8 but if it failes retry to decrypt with iso-8859-1 (because old keys created by different sdks used it)
                        CheckISO88591Validity(password); // check before if there is a char > 255 which is not iso encodable
                        return DecryptPrivateKey(encryptedPrivateKey, password, "iso-8859-1");
                    }
                    throw new InvalidPasswordException("Could not decrypt private key. Invalid private key password.", e);
                } else {
                    throw new CryptoException("Could not decrypt private key.", e);
                }
            } catch (Exception e) {
                throw new CryptoException("Could not decrypt private key.", e);
            } finally {
                p.ClearPasswordArray();
            }
        }


        /// <summary>
        /// Checks if a user key pair can be unlocked.
        /// </summary>
        /// <param name="userKeyPair">The user key pair which should be unlocked.</param>
        /// <param name="password">The password which secures the private key</param>
        /// <returns>True if the user key pair could be unlocked. Otherwise false.</returns>
        /// <exception cref="InvalidKeyPairException">If the provided key pair is invalid.</exception>
        /// <exception cref="CryptoException">If an unexpected error in the decryption of the private key occured.</exception>
        public static bool CheckUserKeyPair(UserKeyPair userKeyPair, char[] password) {
            ValidateUserKeyPair(userKeyPair);
            ValidateUserPrivateKey(userKeyPair.UserPrivateKey);

            if (password == null || password.Length == 0) {
                return false;
            }

            try {
                DecryptPrivateKey(userKeyPair.UserPrivateKey.PrivateKey, password);
            } catch (InvalidPasswordException) {
                return false;
            }
            return true;
        }
        #endregion

        #region Asymmetric encryption and decryption

        private static IDigest SelectMgf1Hash(UserKeyPairAlgorithm algorithm) {
            IDigest mgf1Hashing = null;
            switch (algorithm) {
                case UserKeyPairAlgorithm.RSA2048:
                    mgf1Hashing = new Sha1Digest();
                    break;
                case UserKeyPairAlgorithm.RSA4096:
                    mgf1Hashing = new Sha256Digest();
                    break;
            }
            return mgf1Hashing;
        }

        /// <summary>
        /// Encrypts a file key.
        /// </summary>
        /// <param name="plainFileKey">The file key to encrypt.</param>
        /// <param name="userPublicKey">The public key which should be used for the encryption.</param>
        /// <returns>The encrypted file key.</returns>
        /// <exception cref="InvalidFileKeyException">If the provided file key is invalid.</exception>
        /// <exception cref="InvalidKeyPairException">If the provided public key is invalid.</exception>
        /// <exception cref="CryptoException">If an unexpected error occured.</exception>
        public static EncryptedFileKey EncryptFileKey(PlainFileKey plainFileKey, UserPublicKey userPublicKey) {
            ValidatePlainFileKey(plainFileKey);
            ValidateUserPublicKey(userPublicKey);
            ValidateFileKeyCompatibility(userPublicKey.Version.GetStringValue(), plainFileKey.Version.GetStringValue());

            AsymmetricKeyParameter pubKey = ConvertPublicKey(userPublicKey.PublicKey);
            byte[] eFileKey = null;
            byte[] pFileKey = null;
            EncryptedFileKey encFileKey = null;
            try {
                OaepEncoding engine = new OaepEncoding(new RsaEngine(), new Sha256Digest(), SelectMgf1Hash(userPublicKey.Version), null);
                engine.Init(true, pubKey);
                pFileKey = Convert.FromBase64CharArray(plainFileKey.Key, 0, plainFileKey.Key.Length);
                eFileKey = engine.ProcessBlock(pFileKey, 0, pFileKey.Length);
                encFileKey = new EncryptedFileKey() {
                    Key = Convert.ToBase64String(eFileKey),
                    Iv = plainFileKey.Iv,
                    Tag = plainFileKey.Tag,
                    Version = plainFileKey.Version.ParsePlainFileKeyAlgorithm(userPublicKey.Version)
                };
            } catch (Exception e) {
                throw new CryptoException("Could not encrypt file key. Encryption failed.", e);
            } finally {
                if (eFileKey != null) {
                    Array.Clear(pFileKey, 0, pFileKey.Length);
                }
                if (pFileKey != null) {
                    Array.Clear(pFileKey, 0, pFileKey.Length);
                }
            }

            return encFileKey;
        }

        /// <summary>
        /// Decrypts a file key.
        /// </summary>
        /// <param name="encFileKey">The file key to decrypt.</param>
        /// <param name="userPrivateKey">The private key which should be used for the decryption.</param>
        /// <param name="password">The password which secures the private key.</param>
        /// <returns>The decrypted file key.</returns>
        /// <exception cref="InvalidFileKeyException">If the provided encrypted file key is invalid.</exception>
        /// <exception cref="InvalidKeyPairException">If the provided private key is invalid.</exception>
        /// <exception cref="InvalidPasswordException">If the provided private key password is invalid</exception>
        /// <exception cref="CryptoException">If an unexpected error in the decryption occured.</exception>
        public static PlainFileKey DecryptFileKey(EncryptedFileKey encFileKey, UserPrivateKey userPrivateKey, char[] password) {
            ValidateEncryptedFileKey(encFileKey);
            ValidateUserPrivateKey(userPrivateKey);
            ValidatePassword(password);
            ValidateFileKeyCompatibility(userPrivateKey.Version.GetStringValue(), encFileKey.Version.GetStringValue());

            AsymmetricKeyParameter privateKey = DecryptPrivateKey(userPrivateKey.PrivateKey, password);
            byte[] dFileKey = null;
            char[] charKey = null;
            PlainFileKey plainFileKey = null;
            try {
                OaepEncoding engine = new OaepEncoding(new RsaEngine(), new Sha256Digest(), SelectMgf1Hash(userPrivateKey.Version), null);
                engine.Init(false, privateKey);
                byte[] eFileKey = Convert.FromBase64String(encFileKey.Key);
                dFileKey = engine.ProcessBlock(eFileKey, 0, eFileKey.Length);
                charKey = new char[DetectBase64ArrayLengthRequirement(dFileKey.Length)];
                Convert.ToBase64CharArray(dFileKey, 0, dFileKey.Length, charKey, 0);
                plainFileKey = new PlainFileKey() {
                    Key = charKey,
                    Iv = encFileKey.Iv,
                    Tag = encFileKey.Tag,
                    Version = encFileKey.Version.ParseEncryptedAlgorithm()
                };
            } catch (InvalidCipherTextException e) {
                throw new CryptoException("Could not decrypt file key. Decryption failed.", e);
            } finally {
                if (dFileKey != null) {
                    Array.Clear(dFileKey, 0, dFileKey.Length);
                }
            }
            return plainFileKey;
        }
        #endregion

        #region Symmetric encryption and decryption

        /// <summary>
        /// Generates a random file key.
        /// </summary>
        /// <param name="version">The encryption version for which the file key should be created.</param>
        /// <returns>The generated file key.</returns>
        /// <exception cref="InvalidFileKeyException">If the version for the file key is not supported.</exception>
        public static PlainFileKey GenerateFileKey(PlainFileKeyAlgorithm version) {
            byte[] key = new byte[ParseSymmetricKeyLength(version)];
            new SecureRandom().NextBytes(key);
            byte[] iv = new byte[IvSize];
            new SecureRandom().NextBytes(iv);

            char[] charKey = new char[DetectBase64ArrayLengthRequirement(key.Length)];
            Convert.ToBase64CharArray(key, 0, key.Length, charKey, 0);

            PlainFileKey fileKey = new PlainFileKey() {
                Key = charKey,
                Iv = Convert.ToBase64String(iv),
                Tag = null,
                Version = version
            };
            Array.Clear(key, 0, key.Length);
            Array.Clear(iv, 0, iv.Length);
            return fileKey;
        }

        /// <summary>
        /// Creates a file encryption cipher.
        /// </summary>
        /// <param name="fileKey">The file key which should be used for the encryption.</param>
        /// <returns>The file encryption cipher.</returns>
        /// <exception cref="InvalidFileKeyException">If the provided file key is invalid.</exception>
        /// <exception cref="CryptoSystemException">If an unexpected error occured.</exception>
        public static FileEncryptionCipher CreateFileEncryptionCipher(PlainFileKey fileKey) {
            ValidatePlainFileKey(fileKey);
            return new FileEncryptionCipher(fileKey);
        }
        /// <summary>
        /// Creates a file decryption cipher.
        /// </summary>
        /// <param name="fileKey">The file key which should be used for the decryption.</param>
        /// <returns>The file decryption cipher</returns>
        /// <exception cref="InvalidFileKeyException">If the provided file key is invalid.</exception>
        /// <exception cref="CryptoSystemException">If an unexpected error occured.</exception>
        public static FileDecryptionCipher CreateFileDecryptionCipher(PlainFileKey fileKey) {
            ValidatePlainFileKey(fileKey);
            return new FileDecryptionCipher(fileKey);
        }
        #endregion

        #region Utilities

        /// <summary>
        /// Converts a byte array into a char array.
        /// </summary>
        /// <param name="bytes">The byte array.</param>
        /// <returns>The char array.</returns>
        public static char[] ConvertBytesToChars(byte[] bytes) {
            if (bytes == null) {
                return new char[0];
            }

            char[] chars = new char[bytes.Length];
            for (int i = 0; i != chars.Length; i++) {
                chars[i] = (char) bytes[i];
            }
            return chars;
        }

        private static void CheckISO88591Validity(char[] chars) {
            if(Array.Exists(chars, current => current > 255)) {
                throw new InvalidPasswordException("Could not decrypt private key. Invalid private key password.");
            }
        }

        private static string ConvertPublicKey(AsymmetricKeyParameter pubKey) {
            using (TextWriter txtWriter = new StringWriter()) {
                using (PemWriter pemWriter = new PemWriter(txtWriter)) {
                    pemWriter.WriteObject(pubKey);
                    pemWriter.Writer.Flush();
                    return txtWriter.ToString();
                }
            }
        }

        private static AsymmetricKeyParameter ConvertPublicKey(string pubKeyString) {
            Environment.SetEnvironmentVariable("Org.BouncyCastle.Asn1.AllowUnsafeInteger", "true", EnvironmentVariableTarget.Process);
            AsymmetricKeyParameter pubKey = null;
            using (TextReader txtReader = new StringReader(pubKeyString)) {
                using (PemReader pemReader = new PemReader(txtReader)) {
                    pubKey = (AsymmetricKeyParameter) pemReader.ReadObject();
                }
            }
            return pubKey;
        }

        private static long DetectBase64ArrayLengthRequirement(long sourceArrayLength) {
            // Convert the binary input into Base64 UUEncoded output.
            // Each 3 byte sequence in the source data becomes a 4 byte
            // sequence in the character array.
            long result = (long) ((4.0d / 3.0d) * sourceArrayLength);

            // If array length is not divisible by 4, go up to the next
            // multiple of 4.
            if (result % 4 != 0) {
                result += 4 - result % 4;
            }
            return result;
        }

        #endregion

        #region Validators

        private static void ValidateFileKeyCompatibility(string keyPairAlgorithm, string fileKeyAlgorithm) {
            string[] fileKeyParts = fileKeyAlgorithm.Split('/');
            if (!"A".Equals(fileKeyAlgorithm) && !keyPairAlgorithm.Equals(fileKeyParts[0])) {
                throw new InvalidFileKeyException("User key pair algorithm " + keyPairAlgorithm + " and file key algorithm " + fileKeyAlgorithm + " are not compatible.");
            }
        }

        /// <summary>
        /// Checks the private key of a user.
        /// </summary>
        /// <param name="privateKey">The private key to check.</param>
        /// <exception cref="Dracoon.Crypto.Sdk.InvalidKeyPairException"/>
        private static void ValidateUserPrivateKey(UserPrivateKey privateKey) {
            if (privateKey == null) {
                throw new InvalidKeyPairException("Private key container cannot be null.");
            }
            if (privateKey.PrivateKey == null || privateKey.PrivateKey.Length == 0) {
                throw new InvalidKeyPairException("Private key cannot be null or empty.");
            }
        }

        /// <summary>
        /// Checks the key pair (private and public key) of a user.
        /// </summary>
        /// <param name="userKeyPair">The key pair to check.</param>
        /// <exception cref="InvalidKeyPairException"/>
        private static void ValidateUserKeyPair(UserKeyPair userKeyPair) {
            if (userKeyPair == null) {
                throw new InvalidKeyPairException("User key pair cannot be null.");
            }
        }

        /// <summary>
        /// Checks the password from the user.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <exception cref="InvalidPasswordException"/>
        private static void ValidatePassword(char[] password) {
            if (password == null || password.Length == 0) {
                throw new InvalidPasswordException("Password cannot be null or empty.");
            }
        }

        /// <summary>
        /// Checks the public key of a user.
        /// </summary>
        /// <param name="publicKey">The public key to check.</param>
        /// <exception cref="InvalidKeyPairException"/>
        private static void ValidateUserPublicKey(UserPublicKey publicKey) {
            if (publicKey == null) {
                throw new InvalidKeyPairException("Public key container cannot be null.");
            }
            if (string.IsNullOrEmpty(publicKey.PublicKey)) {
                throw new InvalidKeyPairException("Public key cannot be null or empty.");
            }
        }

        /// <summary>
        /// Checks the file key for file encryption.
        /// </summary>
        /// <param name="fileKey">The file key to check.</param>
        /// <exception cref="InvalidFileKeyException"/>
        private static void ValidatePlainFileKey(PlainFileKey fileKey) {
            if (fileKey == null) {
                throw new InvalidFileKeyException("File key cannot be null.");
            }
        }

        /// <summary>
        /// Checks the encrypted file key for file encryption.
        /// </summary>
        /// <param name="encFileKey">The encrypted file key to check.</param>
        /// /// <exception cref="InvalidFileKeyException"/>
        private static void ValidateEncryptedFileKey(EncryptedFileKey encFileKey) {
            if (encFileKey == null) {
                throw new InvalidFileKeyException("File key cannot be null.");
            }
        }

        #endregion
    }
}
