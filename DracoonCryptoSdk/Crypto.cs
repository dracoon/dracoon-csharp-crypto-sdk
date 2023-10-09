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
using Dracoon.Crypto.Sdk.Model;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Dracoon.Crypto.Sdk {
    /// <summary>
    /// <para>This class is the main class of the Secure Data Space Crypto Library.</para>
    /// <para/>
    /// The class provides methods for:
    /// <list type="bullet">
    /// 
    /// <item>
    /// <description>User key pair generation: 
    /// <see cref="Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm, string)"/>
    /// </description>
    /// </item>
    /// 
    /// <item>
    /// <description>User key pair check: 
    /// <see cref="Crypto.CheckUserKeyPair(UserKeyPair, string)"/>
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
    /// <see cref="Crypto.DecryptFileKey(EncryptedFileKey, UserPrivateKey, string)"/>
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
        }

        private const int pbkdf2HashIterationCount = 1300000;
        private const int pbkdf2SaltSize = 20;
        private const int IvSize = 12;

        private static AsymmetricCipherKeyPair ParseAsymmetricCypherKeyPair(UserKeyPairAlgorithm algorithm) {
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
        public static UserKeyPair GenerateUserKeyPair(UserKeyPairAlgorithm algorithm, string password) {
            ValidatePassword(password);

            AsymmetricCipherKeyPair rsaKeyInfo = ParseAsymmetricCypherKeyPair(algorithm);

            string encryptedPrivateKeyString = EncryptPrivateKey(rsaKeyInfo.Private, password);
            string publicKeyString = ConvertPublicKey(rsaKeyInfo.Public);

            UserPrivateKey userPrivateKey = new UserPrivateKey() { Version = algorithm, PrivateKey = encryptedPrivateKeyString };
            UserPublicKey userPublicKey = new UserPublicKey() { Version = algorithm, PublicKey = publicKeyString };

            return new UserKeyPair() { UserPrivateKey = userPrivateKey, UserPublicKey = userPublicKey };
        }

        private static string EncryptPrivateKey(AsymmetricKeyParameter privateKey, string password) {

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
                pkcs5S2Gen.Init(PKCS5PasswordToBytes(password.ToCharArray()), keySalt, pbkdf2HashIterationCount);
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
                StringWriter txtWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(txtWriter);
                pemWriter.WriteObject(pkPemObject);
                pemWriter.Writer.Close();
                return txtWriter.ToString();
            } catch (Exception e) {
                throw new CryptoException("Could not encrypt private key.", e);
            }
        }

        private static AsymmetricKeyParameter DecryptPrivateKey(string privateKey, string password) {
            Environment.SetEnvironmentVariable("Org.BouncyCastle.Asn1.AllowUnsafeInteger", "true", EnvironmentVariableTarget.Process);
            try {
                AsymmetricKeyParameter decryptedPrivateKey;
                using (TextReader txtReader = new StringReader(privateKey)) {
                    PemReader pemReader = new PemReader(txtReader, new Password(password.ToCharArray()));
                    decryptedPrivateKey = (AsymmetricKeyParameter) pemReader.ReadObject();
                }
                return decryptedPrivateKey;
            } catch (PemException e) {
                if (e.Message.StartsWith("problem creating ENCRYPTED private key: Org.BouncyCastle.Crypto.InvalidCipherTextException")) {
                    throw new InvalidPasswordException("Could not decrypt private key. Invalid private key password.", e);
                } else {
                    throw new CryptoException("Could not decrypt private key.", e);
                }
            } catch (Exception e) {
                throw new CryptoException("Could not decrypt private key.", e);
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
        public static bool CheckUserKeyPair(UserKeyPair userKeyPair, string password) {
            ValidateUserKeyPair(userKeyPair);
            ValidateUserPrivateKey(userKeyPair.UserPrivateKey);

            if (string.IsNullOrEmpty(password)) {
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
            byte[] eFileKey;
            try {
                OaepEncoding engine = new OaepEncoding(new RsaEngine(), new Sha256Digest(), SelectMgf1Hash(userPublicKey.Version), null);
                engine.Init(true, pubKey);
                byte[] pFileKey = Convert.FromBase64String(plainFileKey.Key);
                eFileKey = engine.ProcessBlock(pFileKey, 0, pFileKey.Length);
            } catch (Exception e) {
                throw new CryptoException("Could not encrypt file key. Encryption failed.", e);
            }
            EncryptedFileKey encFileKey = new EncryptedFileKey() {
                Key = Convert.ToBase64String(eFileKey),
                Iv = plainFileKey.Iv,
                Tag = plainFileKey.Tag,
                Version = plainFileKey.Version.ParsePlainFileKeyAlgorithm(userPublicKey.Version)
            };
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
        public static PlainFileKey DecryptFileKey(EncryptedFileKey encFileKey, UserPrivateKey userPrivateKey, string password) {
            ValidateEncryptedFileKey(encFileKey);
            ValidateUserPrivateKey(userPrivateKey);
            ValidatePassword(password);
            ValidateFileKeyCompatibility(userPrivateKey.Version.GetStringValue(), encFileKey.Version.GetStringValue());

            AsymmetricKeyParameter privateKey = DecryptPrivateKey(userPrivateKey.PrivateKey, password);
            byte[] dFileKey;
            try {
                OaepEncoding engine = new OaepEncoding(new RsaEngine(), new Sha256Digest(), SelectMgf1Hash(userPrivateKey.Version), null);
                engine.Init(false, privateKey);
                byte[] eFileKey = Convert.FromBase64String(encFileKey.Key);
                dFileKey = engine.ProcessBlock(eFileKey, 0, eFileKey.Length);
            } catch (InvalidCipherTextException e) {
                throw new CryptoException("Could not decrypt file key. Decryption failed.", e);
            }

            PlainFileKey plainFileKey = new PlainFileKey() {
                Key = Convert.ToBase64String(dFileKey),
                Iv = encFileKey.Iv,
                Tag = encFileKey.Tag,
                Version = encFileKey.Version.ParseEncryptedAlgorithm()
            };
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

            PlainFileKey fileKey = new PlainFileKey() {
                Key = Convert.ToBase64String(key),
                Iv = Convert.ToBase64String(iv),
                Tag = null,
                Version = version
            };
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
        /// Converts a char array into a byte array.
        /// </summary>
        /// <param name="password">The password as char array.</param>
        /// <returns>The password as byte array.</returns>
        public static byte[] PKCS5PasswordToBytes(char[] password) {
            if (password == null) {
                return new byte[0];
            }

            byte[] bytes = new byte[password.Length];
            for (int i = 0; i != bytes.Length; i++) {
                bytes[i] = (byte) password[i];
            }
            return bytes;
        }

        private static string ConvertPublicKey(AsymmetricKeyParameter pubKey) {
            using (TextWriter txtWriter = new StringWriter()) {
                PemWriter pemWriter = new PemWriter(txtWriter);
                pemWriter.WriteObject(pubKey);
                pemWriter.Writer.Flush();
                return txtWriter.ToString();
            }
        }

        private static AsymmetricKeyParameter ConvertPublicKey(string pubKeyString) {
            Environment.SetEnvironmentVariable("Org.BouncyCastle.Asn1.AllowUnsafeInteger", "true", EnvironmentVariableTarget.Process);
            AsymmetricKeyParameter pubKey;
            using (TextReader txtReader = new StringReader(pubKeyString)) {
                PemReader pemReader = new PemReader(txtReader);
                pubKey = (AsymmetricKeyParameter) pemReader.ReadObject();
            }
            return pubKey;
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
            if (string.IsNullOrEmpty(privateKey.PrivateKey)) {
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
        private static void ValidatePassword(string password) {
            if (string.IsNullOrEmpty(password)) {
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
