[![Build Status](https://travis-ci.com/dracoon/dracoon-csharp-crypto-sdk.svg?branch=master)](https://travis-ci.com/dracoon/)
# Dracoon C# Crypto SDK

A library which implements the client-side encryption of Dracoon.

# Introduction

A document which describes the client-side encryption in detail can be found here:

https://support.dracoon.com/hc/en-us/articles/360000986345 

# Setup

#### Minimum Requirements

.NET 2

#### Download

NuGet: Add the this dependency to your packages.config:
If you're using nuget with package management "Packages.config", then edit your project's "packages.config" and add this to the packages section:
```xml
<package id="Dracoon.Crypto.Sdk" version="2.1.0" />
```
If you are using Visual Studio 2017 (or higher) add you're using nuget with package management "PackageReference" then edit your .csproj file and add this to the package dependency group:
```xml
<PackageReference Include="Dracoon.Crypto.Sdk" Version="2.1.0" />
```

DLL import: The latest DLL can be found [here](https://github.com/dracoon/dracoon-csharp-crypto-sdk/releases).

Note that you also need to include the following dependencies:
1. Bouncy Castle Provider (v1.8.6.1): https://www.nuget.org/packages/BouncyCastle/

# Example

An example can be found here: `DracoonCryptoSdkExample/Program.cs`

The example shows the complete encryption workflow, i.e. generate user keypair, validate user keypair, generate file key, encrypt file key, and finally encrypt and decrypt a file.

```c#
static void Main(String[] args) {
    // --- INITIALIZATION ---
    // Generate key pair
    UserKeyPair userKeyPair = Crypto.GenerateUserKeyPair(USER_PASSWORD);
    // Check key pair
    if (!Crypto.CheckUserKeyPair(userKeyPair, USER_PASSWORD)) {
        ...
    }

    byte[] plainData = Encoding.UTF8.GetBytes(DATA);

    ...

    // --- ENCRYPTION ---
    // Generate plain file key
    PlainFileKey fileKey = Crypto.GenerateFileKey();
    // Encrypt blocks
    byte[] encData = EncryptData(fileKey, plainData);
    // Encrypt file key
    EncryptedFileKey encFileKey = Crypto.EncryptFileKey(fileKey, userKeyPair.UserPublicKey);

    ...

    // --- DECRYPTION ---
    // Decrypt file key
    PlainFileKey decFileKey = Crypto.DecryptFileKey(encFileKey, userKeyPair.UserPrivateKey, USER_PASSWORD);
    // Decrypt blocks
    byte[] decData = DecryptData(decFileKey, encData);
}
```

# Copyright and License

Copyright 2017 Dracoon GmbH. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.