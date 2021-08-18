using Microsoft.VisualStudio.TestTools.UnitTesting;
using Dracoon.Crypto.Sdk.Model;
using System;
using System.IO;
using System.Text;

namespace Dracoon.Crypto.Sdk.Test {
    [TestClass]
    public class FileEncryptionCipherTests {

        #region Single block encryption tests

        [TestMethod]
        public void TestEncryptSingleBlock_Success() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.csharp_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.csharp_aes256gcm_enc_file));

            PlainDataContainer testPdc = new PlainDataContainer(pfc);
            EncryptedDataContainer testEdc = TestEncryptSingleBlock(pfk, testPdc);

            CollectionAssert.AreEqual(efc, testEdc.Content, "File content does not match!");
            CollectionAssert.AreEqual(ft, testEdc.Tag, "File tag does not match!");
        }

        [TestMethod]
        public void TestEncryptSingleBlock_DifferentContent() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] pfc = Convert.FromBase64String(TestResources.plain_file_modified);
            byte[] efc = TestResources.csharp_aes256gcm_enc_file;

            PlainDataContainer testPdc = new PlainDataContainer(pfc);
            EncryptedDataContainer testEdc = TestEncryptSingleBlock(pfk, testPdc);

            CollectionAssert.AreNotEqual(efc, testEdc.Content, "File content does match!");
        }

        [TestMethod]
        public void TestEncryptSingleBlock_DifferentTag() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.plain_file_key_bad_tag);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = TestResources.csharp_plain_file;

            PlainDataContainer testPdc = new PlainDataContainer(pfc);
            EncryptedDataContainer testEdc = TestEncryptSingleBlock(pfk, testPdc);

            CollectionAssert.AreNotEqual(ft, testEdc.Tag, "File tag does not match!");
        }

        [TestMethod]
        public void TestEncryptSingleBlock_DifferentKey() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.plain_file_key_bad_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = TestResources.csharp_plain_file;
            byte[] efc = TestResources.csharp_aes256gcm_enc_file;

            PlainDataContainer testPdc = new PlainDataContainer(pfc);
            EncryptedDataContainer testEdc = TestEncryptSingleBlock(pfk, testPdc);

            CollectionAssert.AreNotEqual(efc, testEdc.Content, "File content does match!");
            CollectionAssert.AreNotEqual(ft, testEdc.Tag, "File tag does match!");
        }

        [TestMethod]
        public void TestEncryptSingleBlock_DifferentIv() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.plain_file_key_bad_iv);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = TestResources.csharp_plain_file;
            byte[] efc = TestResources.csharp_aes256gcm_enc_file;

            PlainDataContainer testPdc = new PlainDataContainer(pfc);
            EncryptedDataContainer testEdc = TestEncryptSingleBlock(pfk, testPdc);

            CollectionAssert.AreNotEqual(efc, testEdc.Content, "File content does match!");
            CollectionAssert.AreNotEqual(ft, testEdc.Tag, "File tag does match!");
        }

        private static EncryptedDataContainer TestEncryptSingleBlock(PlainFileKey pfk, PlainDataContainer pdc) {
            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                EncryptedDataContainer currentEdc = encCipher.ProcessBytes(pdc);
                output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                currentEdc = encCipher.DoFinal();
                output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                return new EncryptedDataContainer(output.ToArray(), currentEdc.Tag);
            }
        }

        #endregion

        #region Multi block encryption tests

        [TestMethod]
        public void Test_FileEncrypt_AES256GCM_CSharp() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.csharp_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.csharp_aes256gcm_enc_file));

            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                using (MemoryStream input = new MemoryStream(pfc)) {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0) {
                        byte[] blockBytes = new byte[bytesRead];
                        Array.Copy(buffer, blockBytes, bytesRead);
                        EncryptedDataContainer currentEdc = encCipher.ProcessBytes(new PlainDataContainer(blockBytes));
                        output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                    }
                }
                EncryptedDataContainer testEdc = encCipher.DoFinal();
                output.Write(testEdc.Content, 0, testEdc.Content.Length);

                byte[] testFt = testEdc.Tag;
                byte[] testEfc = output.ToArray();

                CollectionAssert.AreEqual(efc, testEfc, "File content does not match!");
                CollectionAssert.AreEqual(ft, testFt, "File tag does not match!");
            }
        }

        [TestMethod]
        public void Test_FileEncrypt_AES256GCM_Ruby() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.ruby_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.ruby_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.ruby_aes256gcm_enc_file));

            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                using (MemoryStream input = new MemoryStream(pfc)) {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0) {
                        byte[] blockBytes = new byte[bytesRead];
                        Array.Copy(buffer, blockBytes, bytesRead);
                        EncryptedDataContainer currentEdc = encCipher.ProcessBytes(new PlainDataContainer(blockBytes));
                        output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                    }
                }
                EncryptedDataContainer testEdc = encCipher.DoFinal();
                output.Write(testEdc.Content, 0, testEdc.Content.Length);

                byte[] testFt = testEdc.Tag;
                byte[] testEfc = output.ToArray();

                CollectionAssert.AreEqual(efc, testEfc, "File content does not match!");
                CollectionAssert.AreEqual(ft, testFt, "File tag does not match!");
            }
        }

        [TestMethod]
        public void Test_FileEncrypt_AES256GCM_Java() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.java_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.java_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.java_aes256gcm_enc_file));

            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                using (MemoryStream input = new MemoryStream(pfc)) {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0) {
                        byte[] blockBytes = new byte[bytesRead];
                        Array.Copy(buffer, blockBytes, bytesRead);
                        EncryptedDataContainer currentEdc = encCipher.ProcessBytes(new PlainDataContainer(blockBytes));
                        output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                    }
                }
                EncryptedDataContainer testEdc = encCipher.DoFinal();
                output.Write(testEdc.Content, 0, testEdc.Content.Length);

                byte[] testFt = testEdc.Tag;
                byte[] testEfc = output.ToArray();

                CollectionAssert.AreEqual(efc, testEfc, "File content does not match!");
                CollectionAssert.AreEqual(ft, testFt, "File tag does not match!");
            }
        }

        [TestMethod]
        public void Test_FileEncrypt_AES256GCM_Swift() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.swift_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.swift_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.swift_aes256gcm_enc_file));

            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                using (MemoryStream input = new MemoryStream(pfc)) {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0) {
                        byte[] blockBytes = new byte[bytesRead];
                        Array.Copy(buffer, blockBytes, bytesRead);
                        EncryptedDataContainer currentEdc = encCipher.ProcessBytes(new PlainDataContainer(blockBytes));
                        output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                    }
                }
                EncryptedDataContainer testEdc = encCipher.DoFinal();
                output.Write(testEdc.Content, 0, testEdc.Content.Length);

                byte[] testFt = testEdc.Tag;
                byte[] testEfc = output.ToArray();

                CollectionAssert.AreEqual(efc, testEfc, "File content does not match!");
                CollectionAssert.AreEqual(ft, testFt, "File tag does not match!");
            }
        }

        [TestMethod]
        public void Test_FileEncrypt_AES256GCM_JS() {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.js_fk_rsa2048_aes256gcm_plain_file_key);
            byte[] ft = Convert.FromBase64String(pfk.Tag);
            byte[] pfc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.js_plain_file));
            byte[] efc = Convert.FromBase64String(Encoding.UTF8.GetString(TestResources.js_aes256gcm_enc_file));

            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);

            using (MemoryStream output = new MemoryStream()) {
                using (MemoryStream input = new MemoryStream(pfc)) {
                    byte[] buffer = new byte[16];
                    int bytesRead;
                    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) != 0) {
                        byte[] blockBytes = new byte[bytesRead];
                        Array.Copy(buffer, blockBytes, bytesRead);
                        EncryptedDataContainer currentEdc = encCipher.ProcessBytes(new PlainDataContainer(blockBytes));
                        output.Write(currentEdc.Content, 0, currentEdc.Content.Length);
                    }
                }
                EncryptedDataContainer testEdc = encCipher.DoFinal();
                output.Write(testEdc.Content, 0, testEdc.Content.Length);

                byte[] testFt = testEdc.Tag;
                byte[] testEfc = output.ToArray();

                CollectionAssert.AreEqual(efc, testEfc, "File content does not match!");
                CollectionAssert.AreEqual(ft, testFt, "File tag does not match!");
            }
        }

        #endregion

        #region Illegal data container tests

        #region ProcessBytes

        [TestMethod]
        public void TestEncryptProcessArguments_InvalidDataContainer() {
            try {
                TestEncryptProcessArguments(null);
            } catch (ArgumentNullException) {
                return;
            }
            Assert.Fail();
        }

        [TestMethod]
        public void TestEncryptProcessArguments_InvalidDataContent() {
            try {
                TestEncryptProcessArguments(new PlainDataContainer(null));
            } catch (ArgumentNullException) {
                return;
            }
            Assert.Fail();
        }

        private static void TestEncryptProcessArguments(PlainDataContainer pdc) {
            PlainFileKey pfk = TestUtilities.ReadTestResource<PlainFileKey>(TestResources.csharp_fk_rsa2048_aes256gcm_plain_file_key);
            FileEncryptionCipher encCipher = Crypto.CreateFileEncryptionCipher(pfk);
            encCipher.ProcessBytes(pdc);
        }

        #endregion

        #endregion

    }
}