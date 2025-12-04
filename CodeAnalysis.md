# Code Analysis for Software Security Engineering
## Code Review Strategy
Before starting the code review, our team anticipated that, with Bitwarden's large and complex codebase, we would have difficulty identifying security-relevant code paths. Additionally, with numerous functions handling sensitive data (such as passwords, TOTP codes, collections, and user permissions), it could be challenging to determine which areas of Bitwarden's code posed the highest risk for vulnerabilities. 

To mitigate some of these challenges, our team decided to conduct our code review using a scenario-based approach using the use cases [we developed previously](https://github.com/ysabum/Software-Assurance/blob/main/RequirementsSSE.md). We identified Common Weakness Enumerations (CWEs) relevant to our indivudal uses cases, then as a group, we decided on which CWEs to prioritize for manual review of Bitwarden's code. We also decided to incorporated automated review using DeepScan.io to further help identify which parts of Bitwarden's code we should be focusing on for code review. The results from automated code review were then compared to the CWEs from manual review.

## Manual Code Review
### [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

**Description:** The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. 
  
**Files Analyzed** 
1. **[crypto-function.service.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/abstractions/crypto-function.service.ts):** File is likely an interface/abstraction for crypto operations used by higher-level services (sign/verify, hash, symmetric/asymmetric operations).

`crypto-function.service.ts` references SHA-1, a broken hash algorithm (AKA cryptographically unsafe), AES-128, which may be considered inadequate in some compliance contexts (e.g., AES-256 may be required), and ECB mode, which is be directly insecure. The code **does** contain the following for each abstraction: 

```
  /**
   * @deprecated HAZMAT WARNING: DO NOT USE THIS FOR NEW CODE. Implement low-level crypto operations
   * in the SDK instead. Further, you should probably never find yourself using this low-level crypto function.
   */
```

Meaning they are deprecated and should not be used in new code, however there is potential that future developers may accidentally use these insecure algorithms in security-critical contexts.

2. **[encrypt.service.implementation.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/encrypt.service.implementation.ts):** File implements an encryption service (high-level encrypt/decrypt wrappers) that uses the lower-level crypto functions/key generation. 

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

Additionally, there is this line of code:

```
if (this.disableType0Decryption && encString.encryptionType === EncryptionType.AesCbc256_B64)
```

AES-CBC itself is not broken if IVs are handled correctly, however, CBC is no longer recommended by NIST for new systems. CBC without AEAD (i.e., GCM, ChaCha20-Poly1305) lacks authenticated encryption. This implementation does not show IV verification or MAC handling (it's likely handled by PureCrypto).

If CBC is used without integrity protection, it is vulnerable to padding oracle attacks. Since this class deliberately still supports CBC (even if it's disabled by a feature flag), it exposes legacy cryptography.

### [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

**Description:** The product uses a broken or risky cryptographic algorithm or protocol.
  
**Files Analyzed** 
1. **[organization-key-encryptor.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/organization-key-encryptor.ts):** File is responsible for implementing the OrganizationEncryptor using an OrgKey and an EncryptService abstraction. It validates inputs and throws an error if key or secret is null/undefined. For encryption, it packs data using a DataPacker then calls encryptService.encryptString(packed, this.key). For decryption, it calls encryptService.decryptString(secret, this.key), unpacks via dataPacker.unpack(...), and returns the unpacked value. 

Relative to CWE-327, there is only indirect risk associated with this file. `organization-key-encryptor.ts` delegates all cryptographic work to EncryptService (an abstraction); any weakness in algorithms or KDF parameters would be found in the concrete EncryptService implementation.

2. **[key-service-legacy-encryptor-provider.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/key-service-legacy-encryptor-provider.ts):** File is a “provider” that adapts legacy organization/user key handling into a stream (RxJS) of encryptors. It creates OrganizationEncryptor instances bound to a particular org key (and similar for user). RxJS observables are used to wire up asynchronous retrieval of organization keys (via KeyService). They are then wrapped with OrganizationKeyEncryptor or other encryptors. File also contains logic to switch between different encryptor implementations depending on whether a “legacy” key is available (hence the name). It coordinates lifecycle and subscription semantics.

Key behaviors are RxJS flows that eventually call constructors, such as:
```
const encryptor = new OrganizationKeyEncryptor(anyOrgId, encryptService, orgKey, dataPacker);

```

Again, relative to CWE-327, there is only indirect risk associated with this file. This file chooses which encryptor implementation to provide (legacy vs modern). Legacy code paths are often where weaker algorithms or deprecated parameter choices live. However, this file does not implement crypto algorithms; it wires up and provides the encryptor.

3. **[web-crypto-function.service.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/web-crypto-function.service.ts):** File is responsible for the implementation of crypto helper functions that wrap Web Crypto and other fallbacks (e.g., hashing, key derivation, RSA/AES operations, etc.). It contains implementations of hash, PBKDF2/Argon2-ish flows, RSA encrypt/decrypt, AES key generation, and a number of test/example usages. This is the largest file and the place where most crypto operations are implemented or delegated to libraries.

Relative to CWE-327, there potentially is direct risk of supporting weak/legacy hashing algorithms. `web-crypto-function.service.ts` contains explicit references to `sha1` and `md5`. If MD5 or SHA-1 is used for security-sensitive uses (password hashing, HMAC, signatures, integrity checks for untrusted data), this would be unsafe. Even if some uses are only for legacy support or tests, future developers may accidentally use MD5/SHA1 in security-critical contexts.

## Automated Code Review

The automated code review tool used for this project is DeepScan.io. Of the 192 issues found, only 6 were labeled high impact, so we focused on those. The remaining 186 were categorized as medium or low impact.

### [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

**Description:** The product dereferences a pointer that it expects to be valid but is NULL. 

**Files Analyzed**
1. **[collection-dialog.component.ts](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/admin-console/organizations/shared/components/collection-dialog/collection-dialog.component.ts):** File defines an Angular dialog used in Bitwarden’s web vault/admin console for:

    - Creating a collection
    - Editing a collection
    - Deleting a collection
    - Managing access permissions for groups & users
    - Selecting parent collections (nested collections)
    - Selecting an organization when multiple organizations are allowed
    - Enforcing org-level collection limits (free vs paid tiers)
    - Handling form validation, warnings, and UI state updates

DeepScan.io highlighted the following lines of code:
```
function parseName(collection: CollectionView) {
  const nameParts = collection.name?.split("/");
  const name = nameParts[nameParts.length - 1];
  const parent = nameParts.length > 1 ? nameParts.slice(0, -1).join("/") : undefined;
  ```

> Variable 'nameParts' may have an undefined value originated from the expression 'collection.name' at line 528 . But its property is accessed at this point without null check.

The file is a large orchestration component, gathering data from multiple services, enabling user interaction, and saving/updating collections via API calls. However, it is not cryptographic; this part is fully UI and business logic.

2. **[vault-v2.component.ts](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/vault/app/vault/vault-v2.component.ts):** File is the main component behind the Vault screen in Bitwarden Desktop/Browser/Web. It controls:
    - which items (ciphers) you see in the vault
    - search, filtering, and navigation
    - loading an item (view/edit/clone)
    - adding, editing, and deleting passwords (ciphers)
    - browsing by folder, collection, or organization
    - showing dialogs (collections, folders, attachments)
    - launching URLs, copying passwords, TOTP
    - listening to internal broadcast messages (events)
    - handling premium feature gating
    - handling sync completion
    - reading query parameters and updating them
    - interacting with dozens of Bitwarden services

DeepScan.io highlighted the following lines of code:
```
      const collections = this.vaultFilterComponent.collections?.fullList.filter(
        (c) => c.id === this.activeFilter.selectedCollectionId,
      );
      if (collections.length > 0) {
        this.addOrganizationId = collections[0].organizationId;
```

> Variable 'collections' may have an undefined value originated from the expression 'this.vaultFilterComponent.collections' at line 973 . But its property is accessed at this point without null check.

However, this file essentially coordinates all vault UI behavior. It is not cryptography; it is almost entirely UI orchestration and application logic.

3. **[desktop-autofill.service.ts](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/autofill/services/desktop-autofill.service.ts):** File defines the Angular service DesktopAutofillService. Its main responsibilities are to initialize native autofill on macOS, synchronize credentials, listen to OS IPC events for FIDO2/passkey operations, covert requests/responses between IPC format and FIDO2 service format, and cleanup on destroy.

DeepScan.io highlighted the following lines of code:
```
      namespace: "autofill",
      command: "sync",
      params: {
        credentials: [...fido2Credentials, ...passwordCredentials],
      },
```

> Variable 'passwordCredentials' may be uninitialized if the false branch of the condition 'status.value.support.password' at line 108 is taken. But its property is accessed at this point without null check.

> Variable 'fido2Credentials' may be uninitialized if the false branch of the condition 'status.value.support.fido2' at line 126 is taken. But its property is accessed at this point without null check.

Relative to CWE-476, most potential null dereferences are guarded by checks and optional chaining. The only minor risk is status.value or status.value.support being null or undefined in sync(). If IPC returns a malformed object, accessing status.value.state.enabled or status.value.support.password could throw. It is low risk if the IPC is trustworthy.

4. **[vault.component.ts](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/vault/app/vault-v3/vault.component.ts):** The file is an Angular component that represents the main interface for a vault in a password manager (likely Bitwarden, given the import paths). It manages the display, addition, editing, deletion, and interaction with various types of ciphers (passwords, cards, identities, secure notes, SSH keys) and associated metadata like collections, folders, and organizations. The component integrates tightly with many services for:
    - User accounts and permissions (AccountService, BillingAccountProfileStateService)
    - Cipher management (CipherService, CipherArchiveService, ViewPasswordHistoryService)
    - Collections and folders (CollectionService, FolderService)
    - Organization management (OrganizationService)
    - UI messaging and events (BroadcasterService, ToastService, DialogService, MessagingService)
    - Synchronization and TOTP (SyncService, TotpService)
    - Clipboard and platform utilities (PlatformUtilsService)

DeepScan.io highlighted the following lines of code:

```
      const collections = this.vaultFilterComponent.collections?.fullList.filter(
        (c) => c.id === this.activeFilter.selectedCollectionId,
      );
      if (collections.length > 0) {
        this.addOrganizationId = collections[0].organizationId;
```
>Variable 'collections' may have an undefined value originated from the expression 'this.vaultFilterComponent.collections' at line 970 . But its property is accessed at this point without null check.

There is potential for NULL pointer dereference if any async data unexpectedly returns null, especially in cipher and activeUserId. Currently, the code mitigates most of these cases with checks, so actual risk is low but not zero.

### [CWE-628: Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

**Description:** The product calls a function, procedure, or routine with arguments that are not correctly specified, leading to always-incorrect behavior and resultant weaknesses.

1. **[default-organization.service.spec.ts](https://github.com/bitwarden/clients/blob/main/libs/common/src/admin-console/services/organization/default-organization.service.spec.ts):** File is a unit test suite for the Angular service DefaultOrganizationService. Its main goals are to verify that the service behaves correctly in various scenarios, including handling null or empty states, updating organizations, and managing sponsorships.

DeepScan.io highlighted the following lines of code:

```
    if (input == null) {
      return undefined;
    }
    return Object.fromEntries(input?.map((i) => [i.id, i]));
  }
```
>The first argument of 'Object.fromEntries()' should be an object. But an undefined value may be passed.

However, the tests verify correct argument handling and null safety. No function calls in the spec use incorrectly specified arguments. By asserting correct behavior, it helps prevent CWE-628 in the service usage.

# Key Findings and Contributions

## Findings Summary

Based on our code review seen above, including manual review and an automated scan of the code, we identified the following major CWEs that could be addressed to improve the overall security of the project:

## Open-Source Contributions

While our team has not made direct code contributions to the upstream Bitwarden OSS project, our work has produced extensive documentation and analysis that could be valuable for future users and maintainers. Specifically, our security-focused investigation and requirements analysis highlight areas where the official documentation may not fully reflect the realities of OSS installations.

For example:

- **SSH Agent Configuration Issue:** The official documentation for the Bitwarden SSH Agent on Linux incorrectly lists the default socket location. Our documentation clarifies the correct path `/home/<user>/.bitwarden-ssh-agent.sock`, which can help prevent misconfigurations.

- **Audit Log Limitations:** We identified several gaps between OSS behavior and documentation, including delayed client-to-server log sync, lack of native immutable log storage, and limited role-based permissions compared to enterprise editions.

- **Feature Gaps in OSS Clients:** Our analysis highlights missing enterprise-level features such as multi-channel notifications, biometric verification, and granular vault scoping, which users should account for when relying solely on the OSS version.

This documentation, along with our scenario-based use cases and assurance cases, could serve as a reference for OSS developers and project managers evaluating Bitwarden. By making these nuances explicit, future contributors or maintainers could improve user guidance, configuration instructions, and security awareness around the OSS deployment.

## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)

## Reflection

Given what we've learned in lecture and from this assignment, our team gained a deeper understanding of how security-focused code review is conducted in large-scale, real-world applications, using Bitwarden as our case study. Overall, this assignment emphasized the importance of a structured code review strategy. That is, by approaching the review with a scenario-based strategy, we were able to focus on areas of the code that are most critical to security, such as handling sensitive data (passwords, TOTP codes) or user permissions. Defining CWEs in advance helped us prioritize review efforts and identify high-risk areas, rather than getting lost in the large amount of code Bitwarden has. 

Additionally, working together to define CWEs, focus areas, and high-risk components reinforced the importance of team alignment and communication in security code reviews. Assigning specific components or functions to individual team members allowed for more thorough coverage and cross-validation of our findings.
