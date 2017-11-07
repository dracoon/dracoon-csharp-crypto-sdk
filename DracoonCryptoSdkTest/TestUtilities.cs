using Newtonsoft.Json;
using System.IO;

namespace Dracoon.Crypto.Sdk.Test {
    class TestUtilities {
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
            return JsonConvert.DeserializeObject<T>(result);
        }
    }
}
