using Microsoft.VisualStudio.TestTools.UnitTesting;
using Dracoon.Crypto.Sdk.Model;

namespace Dracoon.Crypto.Sdk.Test {
    [TestClass()]
    public class CryptoTests {

        #region Key pair creation tests

        #region Success

        [TestMethod()]
        public void TestGenerateUserKeyPair_Success() {
            UserKeyPair testUkp = Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA2048, "Qwer1234");
            Assert.IsNotNull(testUkp, "Key pair is null!");

            UserPrivateKey testPrivateKey = testUkp.UserPrivateKey;
            Assert.IsNotNull(testPrivateKey, "Private key container is null!");
            Assert.IsNotNull(testPrivateKey.Version, "Private key version is null");
            Assert.IsNotNull(testPrivateKey.PrivateKey, "Private key is null!");
            Assert.IsTrue(testPrivateKey.PrivateKey.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Privat ekey is invalid!");
            Assert.AreEqual(testPrivateKey.Version, UserKeyPairAlgorithm.RSA2048, "Private key version is not correct!");

            UserPublicKey testPublicKey = testUkp.UserPublicKey;
            Assert.IsNotNull(testPublicKey, "Public key container is null!");
            Assert.IsNotNull(testPublicKey.Version, "Public key version is null");
            Assert.IsNotNull(testPublicKey.PublicKey, "Public key is null!");
            Assert.IsTrue(testPublicKey.PublicKey.StartsWith("-----BEGIN PUBLIC KEY-----"), "Public ekey is invalid!");
            Assert.AreEqual(testPublicKey.Version, UserKeyPairAlgorithm.RSA2048, "Public key version is not correct!");
        }
        #endregion

        #region Invalid version

        [TestMethod()]
        public void TestGenerateUserKeyPair_VersionNull() {
            try {
                Crypto.GenerateUserKeyPair(new UserKeyPairAlgorithm().ParseAlgorithm(null), "Qwer1234");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
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

        [TestMethod()]
        public void TestGenerateUserKeyPair_PasswordNull() {
            try {
                Crypto.GenerateUserKeyPair(UserKeyPairAlgorithm.RSA2048, null);
            } catch (InvalidPasswordException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
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

        [TestMethod()]
        public void TestCheckUserKeyPair_Success() {
            bool testCheck = TestCheckUserKeyPair(TestResources.private_key, "Pass1234!");

            Assert.IsTrue(testCheck, "User key pair check failed!");
        }
        #endregion

        #region Invalid private key

        [TestMethod()]
        public void TestCheckUserKeyPair_PrivateKeyNull() {
            try {
                TestCheckUserKeyPair(null, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestCheckUserKeyPair_PrivateKeyBadVersion() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_version, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestCheckUserKeyPair_PrivateKeyBadPem() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_pem, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestCheckUserKeyPair_PrivateKeyBadValue() {
            try {
                TestCheckUserKeyPair(TestResources.private_key_bad_value, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        #endregion

        #region Invalid password

        [TestMethod()]
        public void TestCheckUserKeyPair_PasswordNull() {
            bool testCheck = TestCheckUserKeyPair(TestResources.private_key, null);

            Assert.IsFalse(testCheck, "User key pair check was successful!");
        }
        [TestMethod()]
        public void TestCheckUserKeyPair_PasswordInvalid() {
            bool testCheck = TestCheckUserKeyPair(TestResources.private_key, "Invalid-Password");

            Assert.IsFalse(testCheck, "User key pair check was successful!");
        }
        #endregion

        private bool TestCheckUserKeyPair(byte[] ukpFileBytes, string pw) {
            UserKeyPair ukp = new UserKeyPair() {
                UserPrivateKey = TestUtilities.ReadTestResource<UserPrivateKey>(ukpFileBytes)
            };
            return Crypto.CheckUserKeyPair(ukp, pw);
        }
        #endregion

        #region File key encryption tests

        #region Success

        [TestMethod()]
        public void TestEncryptFileKey_Success() {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(TestResources.enc_file_key);
            EncryptedFileKey testEfk = TestEncryptFileKey(TestResources.plain_file_key, TestResources.public_key);

            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.plain_file_key);
            PlainFileKey testPfk = Crypto.DecryptFileKey(testEfk, TestUtilities.ReadTestResource<UserPrivateKey>(TestResources.private_key), "Pass1234!");

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(efk.Iv, testEfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(efk.Tag, testEfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(efk.Version, testEfk.Version, "Version is incorrect!");
        }
        #endregion

        private EncryptedFileKey TestEncryptFileKey(byte[] plainFileKeyResource, byte[] userPublicKeyResource) {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(plainFileKeyResource);
            UserPublicKey upk = TestUtilities.ReadTestResource<UserPublicKey>(userPublicKeyResource);
            return Crypto.EncryptFileKey(pfk, upk);
        }
        #endregion

        #region File key decryption tests

        #region Success

        [TestMethod()]
        public void TestDecryptFileKey_Success() {
            string pw = "Pass1234!";
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.plain_file_key);
            PlainFileKey testPfk = TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key, pw);

            Assert.AreEqual(pfk.Key, testPfk.Key, "File key is incorrect!");
            Assert.AreEqual(pfk.Iv, testPfk.Iv, "Initialization vector is incorrect!");
            Assert.AreEqual(pfk.Tag, testPfk.Tag, "Tag is incorrect!");
            Assert.AreEqual(pfk.Version, testPfk.Version, "Version is incorrect!");
        }
        #endregion

        #region Invalid file key

        [TestMethod()]
        public void TestDecryptFileKey_FileKeyNull() {
            try {
                TestDecryptFileKey(null, TestResources.private_key, "Pass1234!");
            } catch (InvalidFileKeyException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_FileKeyBadVersion() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key_bad_version, TestResources.private_key, "Pass1234!");
            } catch (InvalidFileKeyException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_FileKeyBadKey() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key_bad_key, TestResources.private_key, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        #endregion

        #region Invalid private key

        [TestMethod()]
        public void TestDecryptFileKey_PrivateKeyNull() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, null, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_PrivateKeyBadVersion() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key_bad_version, "Pass1234!");
            } catch (InvalidKeyPairException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_PrivateKeyBadPem() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key_bad_pem, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_PrivateKeyBadValue() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key_bad_value, "Pass1234!");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        #endregion

        #region Invalid password

        [TestMethod()]
        public void TestDecryptFileKey_PasswordNull() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key, null);
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        [TestMethod()]
        public void TestDecryptFileKey_PasswordInvalid() {
            try {
                TestDecryptFileKey(TestResources.enc_file_key, TestResources.private_key, "Invalid-Password");
            } catch (CryptoException) {
                return;
            }
            Assert.Fail();
        }
        #endregion

        private PlainFileKey TestDecryptFileKey(byte[] encryptedFileKeyResource, byte[] userPrivateKeyResource, string password) {
            EncryptedFileKey efk = TestUtilities.ReadTestResource<EncryptedFileKey>(encryptedFileKeyResource);
            UserPrivateKey upk = TestUtilities.ReadTestResource<UserPrivateKey>(userPrivateKeyResource);
            return Crypto.DecryptFileKey(efk, upk, password);
        }
        #endregion

    }
}