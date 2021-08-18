using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.IO;

namespace Dracoon.Crypto.Sdk.Test {
    internal static class TestUtilities {

        internal static T ReadTestResource<T>(byte[] resourceBytes) {
            if (resourceBytes == null || resourceBytes.Length == 0) {
                return default(T);
            }
            string result = "";
            using (MemoryStream ms = new MemoryStream(resourceBytes)) {
                using (StreamReader sr = new StreamReader(ms)) {
                    result = sr.ReadToEnd();
                }
            }
            return JsonConvert.DeserializeObject<T>(result, new JsonConverter[] { new UserFileKeyAlgorithm() });
        }
    }

    internal class UserFileKeyAlgorithm : StringEnumConverter {

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
            string stringValue = (string) reader.Value;
            if (existingValue is UserKeyPairAlgorithm) {
                return new UserKeyPairAlgorithm().ParseAlgorithm(stringValue);
            }
            if (existingValue is PlainFileKeyAlgorithm) {
                return new PlainFileKeyAlgorithm().ParseAlgorithm(stringValue);
            }
            if (existingValue is EncryptedFileKeyAlgorithm) {
                return new EncryptedFileKeyAlgorithm().ParseAlgorithm(stringValue);
            }
            return stringValue;
        }

        public override bool CanConvert(Type objectType) {
            return objectType == typeof(string) || objectType == typeof(UserKeyPairAlgorithm) || objectType == typeof(EncryptedFileKeyAlgorithm) || objectType == typeof(PlainFileKeyAlgorithm);
        }
    }
}
