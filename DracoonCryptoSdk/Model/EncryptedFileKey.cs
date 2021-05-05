namespace Dracoon.Crypto.Sdk.Model {
    public class EncryptedFileKey {

        public string Key { get; set; }

        public string Iv { get; set; }

        public string Tag { get; set; }

        public EncryptedFileKeyAlgorithm Version { get; set; }
    }
}
