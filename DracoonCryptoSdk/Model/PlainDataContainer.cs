namespace Dracoon.Crypto.Sdk.Model {
    public class PlainDataContainer {
        public byte[] Content {
            get; private set;
        }
        public PlainDataContainer(byte[] content) {
            Content = content;
        }
    }
}
