## Manual Code Review
### [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

**Description:** The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. 
  
**Files Analyzed** 
- **[crypto-function.service.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/abstractions/crypto-function.service.ts):** File is likely an interface/abstraction for crypto operations used by higher-level services (sign/verify, hash, symmetric/asymmetric operations).

`crypto-function.service.ts` references SHA-1, a broken hash algorithm (AKA cryptographically unsafe), AES-128, which may be considered inadequate in some compliance contexts (e.g., AES-256 may be required), and ECB mode, which is be directly insecure. The code **does** contain the following for each abstract: 

```
  /**
   * @deprecated HAZMAT WARNING: DO NOT USE THIS FOR NEW CODE. Implement low-level crypto operations
   * in the SDK instead. Further, you should probably never find yourself using this low-level crypto function.
   */
```

Meaning they are deprecated and should not be used in new code, however there is potential that future developers may accidentally use these insecure algorithms in security-critical contexts.

- **[encrypt.service.implementation.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/encrypt.service.implementation.ts):** File implements an encryption service (high-level encrypt/decrypt wrappers) that uses the lower-level crypto functions/key generation. 

Relative to CWE-326, the file contains the following lines of code:

```
async hash(value: string | Uint8Array, algorithm: "sha1" | "sha256" | "sha512"): Promise<string> {
```
```
case EncryptionType.Rsa2048_OaepSha1_B64:
case EncryptionType.Rsa2048_OaepSha1_HmacSha256_B64:
```
```
return this.cryptoFunctionService.rsaDecrypt(data.dataBytes, privateKey, "sha1");
```

Setting "sha1" (SHA-1) as an allowed algorithm is technically insecure. SHA-1 has been formally broken since 2017 and is no longer considered cryptographically strong. Also, RSA-2048 is acceptable but nearing minimum strength in modern recommendations (NIST recommends 3072 bits).


### [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

**Description:** The product uses a broken or risky cryptographic algorithm or protocol.
  
**Files Analyzed** 
- **[organization-key-encryptor.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/organization-key-encryptor.ts):** File is responsible for implementing the OrganizationEncryptor using an OrgKey and an EncryptService abstraction. It validates inputs and throws an error if key or secret is null/undefined. For encryption, it packs data using a DataPacker then calls encryptService.encryptString(packed, this.key). For decryption, it calls encryptService.decryptString(secret, this.key), unpacks via dataPacker.unpack(...), and returns the unpacked value. 

Relative to CWE-327, there is only indirect risk associated with this file. organization-key-encryptor.ts delegates all cryptographic work to EncryptService (an abstraction); any weakness in algorithms or KDF parameters would be found in the concrete EncryptService implementation.

- **[key-service-legacy-encryptor-provider.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/key-service-legacy-encryptor-provider.ts):** File is a “provider” that adapts legacy organization/user key handling into a stream (RxJS) of encryptors. It creates OrganizationEncryptor instances bound to a particular org key (and similar for user). RxJS observables are used to wire up asynchronous retrieval of organization keys (via KeyService). They are then wrapped with OrganizationKeyEncryptor or other encryptors. File also contains logic to switch between different encryptor implementations depending on whether a “legacy” key is available (hence the name). It coordinates lifecycle and subscription semantics.

Key behaviors are RxJS flows that eventually call constructors, such as:
```
const encryptor = new OrganizationKeyEncryptor(anyOrgId, encryptService, orgKey, dataPacker);

```

Again, relative to CWE-327, there is only indirect risk associated with this file. This file chooses which encryptor implementation to provide (legacy vs modern). Legacy code paths are often where weaker algorithms or deprecated parameter choices live. However, this file does not implement crypto algorithms; it wires up and provides the encryptor.

- **[web-crypto-function.service.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/web-crypto-function.service.ts):** File is responsible for the implementation of crypto helper functions that wrap Web Crypto and other fallbacks (e.g., hashing, key derivation, RSA/AES operations, etc.). It contains implementations of hash, PBKDF2/Argon2-ish flows, RSA encrypt/decrypt, AES key generation, and a number of test/example usages. This is the largest file and the place where most crypto operations are implemented or delegated to libraries.

Relative to CWE-327, there potentially is direct risk of supporting weak/legacy hashing algorithms. `web-crypto-function.service.ts` contains explicit references to `sha1` and `md5`. If MD5 or SHA-1 is used for security-sensitive uses (password hashing, HMAC, signatures, integrity checks for untrusted data), this would be unsafe. Even if some uses are only for legacy support or tests, future developers may accidentally use MD5/SHA1 in security-critical contexts.

### [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

**Description:** The product uses a one-way cryptographic hash against an input that should not be reversible, such as a password, but the product does not also use a salt as part of the input.
  
**Files Analyzed** 
- **[enc-string.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/models/enc-string.ts):** File is a utility for converting between strings and encoded forms (base64/utf8/Uint8Array helpers).