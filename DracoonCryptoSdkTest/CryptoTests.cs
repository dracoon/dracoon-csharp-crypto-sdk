using Dracoon.Crypto.Sdk.Model;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Dracoon.Crypto.Sdk.Test {
    [TestClass]
    public class CryptoTests {

        #region Key pair creation tests

        #region Success

        [TestMethod]
        public void TestGenerateKP_RSA2048_Success() {
            UserKeyPair testUkp = Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA2048, "Qwer1234");
            Assert.IsNotNull(testUkp, "Key pair is null!");

            UserPrivateKey testPrivateKey = testUkp.UserPrivateKey;
            Assert.IsNotNull(testPrivateKey, "Private key container is null!");
            Assert.IsNotNull(testPrivateKey.Version, "Private key version is null");
            Assert.IsNotNull(testPrivateKey.PrivateKey, "Private key is null!");
            Assert.IsTrue(testPrivateKey.PrivateKey.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Private key is invalid!");
            Assert.AreEqual(testPrivateKey.Version, UserKeyPairAlgorithm.RSA2048, "Private key version is not correct!");

            UserPublicKey testPublicKey = testUkp.UserPublicKey;
            Assert.IsNotNull(testPublicKey, "Public key container is null!");
            Assert.IsNotNull(testPublicKey.Version, "Public key version is null");
            Assert.IsNotNull(testPublicKey.PublicKey, "Public key is null!");
            Assert.IsTrue(testPublicKey.PublicKey.StartsWith("-----BEGIN PUBLIC KEY-----"), "Public key is invalid!");
            Assert.AreEqual(testPublicKey.Version, UserKeyPairAlgorithm.RSA2048, "Public key version is not correct!");
        }

        [TestMethod]
        public void TestGenerateKP_RSA4096_Success() {
            UserKeyPair testUkp = Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA4096, "Qwer1234");
            Assert.IsNotNull(testUkp, "Key pair is null!");

            UserPrivateKey testPrivateKey = testUkp.UserPrivateKey;
            Assert.IsNotNull(testPrivateKey, "Private key container is null!");
            Assert.IsNotNull(testPrivateKey.Version, "Private key version is null");
            Assert.IsNotNull(testPrivateKey.PrivateKey, "Private key is null!");
            Assert.IsTrue(testPrivateKey.PrivateKey.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Private key is invalid!");
            Assert.AreEqual(testPrivateKey.Version, UserKeyPairAlgorithm.RSA4096, "Private key version is not correct!");

            UserPublicKey testPublicKey = testUkp.UserPublicKey;
            Assert.IsNotNull(testPublicKey, "Public key container is null!");
            Assert.IsNotNull(testPublicKey.Version, "Public key version is null");
            Assert.IsNotNull(testPublicKey.PublicKey, "Public key is null!");
            Assert.IsTrue(testPublicKey.PublicKey.StartsWith("-----BEGIN PUBLIC KEY-----"), "Public key is invalid!");
            Assert.AreEqual(testPublicKey.Version, UserKeyPairAlgorithm.RSA4096, "Public key version is not correct!");
        }

        #endregion

        #region Invalid version

        [TestMethod]
        public void TestGenerateUserKeyPair_VersionNull() {
            try {
                Crypto.GenerateUserKeyPair(new UserKeyPairAlgorithm().ParseAlgorithm(null), "Qwer1234");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestGenerateUserKeyPair_VersionInvalid() {
            try {
                Crypto.GenerateUserKeyPair(new UserKeyPairAlgorithm().ParseAlgorithm("Z"), "Qwer1234");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        #endregion

        #region Invalid password

        [TestMethod]
        public void TestGenerateUserKeyPair_PasswordNull() {
            try {
                Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA2048, null);
            } catch (InvalidPasswordException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestGenerateUserKeyPair_PasswordEmpty() {
            try {
                Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA2048, "");
            } catch (InvalidPasswordException) {
                return;
            }
            Assert.Fail();
        }

        #endregion

        #endregion

        #region Key pair check tests

        #region Success

        [TestMethod]
        public void Test_KP_RSA2048_CSharp() {
            bool testCheck = TestCheckUserKeyPair(TestResources.csharp_kp_rsa2048_private_key, TestResources.csharp_kp_rsa2048_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_CSharp() {
            bool testCheck = TestCheckUserKeyPair(TestResources.csharp_kp_rsa4096_private_key, TestResources.csharp_kp_rsa4096_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_PBKDF2_SHA1_1300k_CSharp() {
            bool testCheck = TestCheckUserKeyPair(TestResources.csharp_kp_rsa4096_pbkdf2_sha1_1300k_private_key, TestResources.csharp_kp_rsa4096_pbkdf2_sha1_1300k_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA2048_Ruby() {
            bool testCheck = TestCheckUserKeyPair(TestResources.ruby_kp_rsa2048_private_key, TestResources.ruby_kp_rsa2048_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_Ruby() {
            bool testCheck = TestCheckUserKeyPair(TestResources.ruby_kp_rsa4096_private_key, TestResources.ruby_kp_rsa4096_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA2048_Java() {
            bool testCheck = TestCheckUserKeyPair(TestResources.java_kp_rsa2048_private_key, TestResources.java_kp_rsa2048_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_Java() {
            bool testCheck = TestCheckUserKeyPair(TestResources.java_kp_rsa4096_private_key, TestResources.java_kp_rsa4096_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_PBKDF2_SHA1_1300k_Java() {
            bool testCheck = TestCheckUserKeyPair(TestResources.java_kp_rsa4096_pbkdf2_sha1_1300k_private_key, TestResources.java_kp_rsa4096_pbkdf2_sha1_1300k_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA2048_Swift() {
            bool testCheck = TestCheckUserKeyPair(TestResources.swift_kp_rsa2048_private_key, TestResources.swift_kp_rsa2048_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_Swift() {
            bool testCheck = TestCheckUserKeyPair(TestResources.swift_kp_rsa4096_private_key, TestResources.swift_kp_rsa4096_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_PBKDF2_SHA1_1300k_Swift() {
            bool testCheck = TestCheckUserKeyPair(TestResources.swift_kp_rsa4096_pbkdf2_sha1_1300k_private_key, TestResources.swift_kp_rsa4096_pbkdf2_sha1_1300k_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA2048_JS() {
            bool testCheck = TestCheckUserKeyPair(TestResources.js_kp_rsa2048_private_key, TestResources.js_kp_rsa2048_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_JS() {
            bool testCheck = TestCheckUserKeyPair(TestResources.js_kp_rsa4096_private_key, TestResources.js_kp_rsa4096_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        [TestMethod]
        public void Test_KP_RSA4096_PBKDF2_SHA1_1300k_JS() {
            bool testCheck = TestCheckUserKeyPair(TestResources.js_kp_rsa4096_pbkdf2_sha1_1300k_private_key, TestResources.js_kp_rsa4096_pbkdf2_sha1_1300k_password);

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }

        #endregion

        #region Invalid private key

        [TestMethod]
        public void TestCheckUserKeyPair_PrivateKeyNull() {
            try {
                TestCheckUserKeyPair(null, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestCheckUserKeyPair_PrivateKeyBadVersion() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_version, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestCheckUserKeyPair_PrivateKeyBadPem() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_pem, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestCheckUserKeyPair_PrivateKeyBadValue() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_value, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestCheckUserKeyPair_PrivateKeyBadAsn1() {
            bool testCheck = TestCheckUserKeyPair(TestResources.private_key_bad_asn1, "Qwer1234!");
            Assert.IsTrue(testCheck, "User key pair ASN1 check failed!");
        }

        #endregion

        #region Invalid password

        [TestMethod]
        public void TestCheckUserKeyPair_PasswordNull() {
            bool testCheck = TestCheckUserKeyPair(TestResources.csharp_kp_rsa2048_private_key, null);

            Assert.IsFalse(testCheck, "User key pair check was successful!");
        }

        [TestMethod]
        public void TestCheckUserKeyPair_PasswordInvalid() {
            bool testCheck = TestCheckUserKeyPair(TestResources.csharp_kp_rsa2048_private_key, "Invalid-Password");

            Assert.IsFalse(testCheck, "User key pair check was successful!");
        }

        #endregion

        private static bool TestCheckUserKeyPair(byte[] ukpFileBytes, string pw) {
            UserKeyPair ukp = new UserKeyPair {
                UserPrivateKey = TestUtilities.ReadTestResource<UserPrivateKey>(ukpFileBytes)
            };
            return Crypto.CheckUserKeyPair(ukp, pw);
        }

        #endregion

        #region File key encryption tests

        #region Success

        [TestMethod]
        public void Test_FKEncrypt_RSA2048_AES256GCM_CSharp() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key, TestResources.csharp_kp_rsa2048_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.csharp_kp_rsa2048_private_key), TestResources.csharp_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }


        [TestMethod]
        public void Test_FKEncrypt_RSA4096_AES256GCM_CSharp() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.csharp_fk_rsa4096_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.csharp_fk_rsa4096_aes256gcm_plain_file_key, TestResources.csharp_kp_rsa4096_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.csharp_kp_rsa4096_private_key), TestResources.csharp_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA2048_AES256GCM_Ruby() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.ruby_fk_rsa2048_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.ruby_fk_rsa2048_aes256gcm_plain_file_key, TestResources.ruby_kp_rsa2048_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.ruby_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.ruby_kp_rsa2048_private_key), TestResources.ruby_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA4096_AES256GCM_Ruby() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.ruby_fk_rsa4096_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.ruby_fk_rsa4096_aes256gcm_plain_file_key, TestResources.ruby_kp_rsa4096_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.ruby_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.ruby_kp_rsa4096_private_key), TestResources.ruby_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA2048_AES256GCM_Java() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.java_fk_rsa2048_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.java_fk_rsa2048_aes256gcm_plain_file_key, TestResources.java_kp_rsa2048_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.java_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.java_kp_rsa2048_private_key), TestResources.java_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA4096_AES256GCM_Java() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.java_fk_rsa4096_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.java_fk_rsa4096_aes256gcm_plain_file_key, TestResources.java_kp_rsa4096_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.java_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.java_kp_rsa4096_private_key), TestResources.java_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA2048_AES256GCM_Swift() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.swift_fk_rsa2048_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.swift_fk_rsa2048_aes256gcm_plain_file_key, TestResources.swift_kp_rsa2048_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.swift_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.swift_kp_rsa2048_private_key), TestResources.swift_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }


        [TestMethod]
        public void Test_FKEncrypt_RSA4096_AES256GCM_Swift() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.swift_fk_rsa4096_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.swift_fk_rsa4096_aes256gcm_plain_file_key, TestResources.swift_kp_rsa4096_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.swift_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.swift_kp_rsa4096_private_key), TestResources.swift_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA2048_AES256GCM_JS() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.js_fk_rsa2048_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.js_fk_rsa2048_aes256gcm_plain_file_key, TestResources.js_kp_rsa2048_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.js_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.js_kp_rsa2048_private_key), TestResources.js_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKEncrypt_RSA4096_AES256GCM_JS() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.js_fk_rsa4096_aes256gcm_enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.js_fk_rsa4096_aes256gcm_plain_file_key, TestResources.js_kp_rsa4096_public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.js_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.js_kp_rsa4096_private_key), TestResources.js_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }

        #endregion

        private static EncryptedFileKey TestEncryptFileKey(byte[] plainFileKeyResource, byte[] userPublicKeyResource) {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(plainFileKeyResource);
            UserPublicKey upk = TestUtilities.ReadTestResource<UserPublicKey>(userPublicKeyResource);
            return Crypto.EncryptFileKey(pfk, upk);
        }

        #endregion

        #region File key decryption tests

        #region Success

        [TestMethod]
        public void Test_FKDecrypt_RSA2048_AES256GCM_CSharp() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.csharp_kp_rsa2048_private_key, TestResources.csharp_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA4096_AES256GCM_CSharp() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.csharp_fk_rsa4096_aes256gcm_enc_file_key, TestResources.csharp_kp_rsa4096_private_key, TestResources.csharp_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA2048_AES256GCM_Ruby() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.ruby_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.ruby_fk_rsa2048_aes256gcm_enc_file_key, TestResources.ruby_kp_rsa2048_private_key, TestResources.ruby_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA4096_AES256GCM_Ruby() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.ruby_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.ruby_fk_rsa4096_aes256gcm_enc_file_key, TestResources.ruby_kp_rsa4096_private_key, TestResources.ruby_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA2048_AES256GCM_Java() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.java_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.java_fk_rsa2048_aes256gcm_enc_file_key, TestResources.java_kp_rsa2048_private_key, TestResources.java_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA4096_AES256GCM_Java() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.java_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.java_fk_rsa4096_aes256gcm_enc_file_key, TestResources.java_kp_rsa4096_private_key, TestResources.java_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA2048_AES256GCM_Swift() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.swift_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.swift_fk_rsa2048_aes256gcm_enc_file_key, TestResources.swift_kp_rsa2048_private_key, TestResources.swift_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA4096_AES256GCM_Swift() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.swift_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.swift_fk_rsa4096_aes256gcm_enc_file_key, TestResources.swift_kp_rsa4096_private_key, TestResources.swift_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA2048_AES256GCM_JS() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.js_fk_rsa2048_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.js_fk_rsa2048_aes256gcm_enc_file_key, TestResources.js_kp_rsa2048_private_key, TestResources.js_kp_rsa2048_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        [TestMethod]
        public void Test_FKDecrypt_RSA4096_AES256GCM_JS() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.js_fk_rsa4096_aes256gcm_plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.js_fk_rsa4096_aes256gcm_enc_file_key, TestResources.js_kp_rsa4096_private_key, TestResources.js_kp_rsa4096_password);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }

        #endregion

        #region Invalid file key

        [TestMethod]
        public void TestDecryptFileKey_FileKeyNull() {
            try {
                TestDecryptFileKey(null, TestResources.csharp_kp_rsa2048_private_key, TestResources.csharp_kp_rsa2048_password);
            } catch (InvalidFileKeyException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_FileKeyBadVersion() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key_bad_version, TestResources.csharp_kp_rsa2048_private_key, TestResources.csharp_kp_rsa2048_password);
            } catch (InvalidFileKeyException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_FileKeyBadKey() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key_bad_key, TestResources.csharp_kp_rsa2048_private_key, TestResources.csharp_kp_rsa2048_password);
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        #endregion

        #region Invalid private key

        [TestMethod]
        public void TestDecryptFileKey_PrivateKeyNull() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, null, TestResources.csharp_kp_rsa2048_password);
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_PrivateKeyBadVersion() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.private_key_bad_version, TestResources.csharp_kp_rsa2048_password);
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_PrivateKeyBadPem() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.private_key_bad_pem, TestResources.csharp_kp_rsa2048_password);
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_PrivateKeyBadValue() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.private_key_bad_value, TestResources.csharp_kp_rsa2048_password);
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        #endregion

        #region Invalid password

        [TestMethod]
        public void TestDecryptFileKey_PasswordNull() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.csharp_kp_rsa2048_private_key, null);
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestDecryptFileKey_PasswordInvalid() {
            try {
                TestDecryptFileKey(TestResources.csharp_fk_rsa2048_aes256gcm_enc_file_key, TestResources.csharp_kp_rsa2048_private_key, "Invalid-Password");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }

        #endregion

        private static PlainFileKey TestDecryptFileKey(byte[] encryptedFileKeyResource, byte[] userPrivateKeyResource, string password) {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(encryptedFileKeyResource);
            UserPrivateKey upk = TestUtilities.ReadTestResource<UserPrivateKey>(userPrivateKeyResource);
            return Crypto.DecryptFileKey(efk, upk, password);
        }

        #endregion

    }
}