﻿using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.IO;
using System.Text;

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
            return JsonConvert.DeserializeObject<T>(result, new JsonConverter[] { new AlgorithmEnumConverter(), new ByteArrayConverter() });
        }
    }

    internal class AlgorithmEnumConverter : StringEnumConverter {

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
            string stringValue = (string) reader.Value;
            if (objectType == typeof(UserKeyPairAlgorithm)) {
                return new UserKeyPairAlgorithm().ParseAlgorithm(stringValue);
            }
            if (objectType == typeof(PlainFileKeyAlgorithm)) {
                return new PlainFileKeyAlgorithm().ParseAlgorithm(stringValue);
            }
            if (objectType == typeof(EncryptedFileKeyAlgorithm)) {
                return new EncryptedFileKeyAlgorithm().ParseAlgorithm(stringValue);
            }
            return stringValue;
        }

        public override bool CanConvert(Type objectType) {
            return objectType == typeof(UserKeyPairAlgorithm) || objectType == typeof(EncryptedFileKeyAlgorithm) || objectType == typeof(PlainFileKeyAlgorithm);
        }
    }

    internal class ByteArrayConverter : JsonConverter {
        public override bool CanConvert(Type objectType) {
            return objectType == typeof(byte[]);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {
            string stringValue = (string) reader.Value;
            return Encoding.UTF8.GetBytes(stringValue);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {

        }
    }

}
