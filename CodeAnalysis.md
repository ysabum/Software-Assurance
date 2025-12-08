# Code Analysis for Software Security Engineering
## Code Review Strategy
Before starting the code review, our team anticipated that, with Bitwarden's large and complex codebase, we would have difficulty identifying security-relevant code paths. Additionally, with numerous functions handling sensitive data (such as passwords, TOTP codes, collections, and user permissions), it could be challenging to determine which areas of Bitwarden's code posed the highest risk for vulnerabilities. 

To mitigate some of these challenges, our team decided to conduct our code review using a scenario-based approach using the use cases [we developed previously](https://github.com/ysabum/Software-Assurance/blob/main/RequirementsSSE.md). We identified Common Weakness Enumerations (CWEs) relevant to our indivudal uses cases, then as a group, we decided on which CWEs to prioritize for manual review of Bitwarden's code. We also decided to incorporated automated review using various automated scanning tools to further help identify which parts of Bitwarden's code we should be focusing on for code review. The results from automated code review were then compared to the CWEs from manual review.

## Manual Code Review
###  [CWE-79: Cross-Site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)

**Description:** The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

**Files Analyzed:** 

- **[`event-export.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event-export.service.ts)**
- **[`event.export.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event.export.ts)**
- **[`index.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/index.ts)**

No direct XSS vulnerability were found. The event export feature only generates **CSV files**, not HTML. Data is never inserted into the DOM. From `event-export.service.ts`, PapaParse only creates text output, which makes XSS unlikely.

There is a small possibility of **CSV formula injection** if a user enters values like `=cmd()`, but this is rare and does not affect the web application itself.


### [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

**Description:** The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required. A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources. 
  
**Files Analyzed:** 
- **[`crypto-function.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/abstractions/crypto-function.service.ts)** 
- **[`encrypt.service.implementation.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/encrypt.service.implementation.ts)**

`crypto-function.service.ts` is likely an interface/abstraction for crypto operations used by higher-level services (sign/verify, hash, symmetric/asymmetric operations). It references SHA-1, a broken hash algorithm (AKA cryptographically unsafe), AES-128, which may be considered inadequate in some compliance contexts (e.g., AES-256 may be required), and ECB mode, which is be directly insecure. The code **does** contain the following for each abstraction: 

```
  /**
   * @deprecated HAZMAT WARNING: DO NOT USE THIS FOR NEW CODE. Implement low-level crypto operations
   * in the SDK instead. Further, you should probably never find yourself using this low-level crypto function.
   */
```

Meaning they are deprecated and should not be used in new code, however there is potential that future developers may accidentally use these insecure algorithms in security-critical contexts.

`encrypt.service.implementation.ts` implements an encryption service (high-level encrypt/decrypt wrappers) that uses the lower-level crypto functions/key generation. Relative to CWE-326, the file contains the following lines of code:

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
  
**Files Analyzed:** 
- **[`organization-key-encryptor.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/organization-key-encryptor.ts)**

- **[`key-service-legacy-encryptor-provider.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/tools/cryptography/key-service-legacy-encryptor-provider.ts)**

- **[`web-crypto-function.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/key-management/crypto/services/web-crypto-function.service.ts)**

There is only indirect risk associated with `organization-key-encryptor.ts`. It delegates all cryptographic work to EncryptService (an abstraction); any weakness in algorithms or KDF parameters would be found in the concrete EncryptService implementation.

Similarly, relative to CWE-327, there is only indirect risk associated with `key-service-legacy-encryptor-provider.ts`. This file chooses which encryptor implementation to provide (legacy vs modern). Legacy code paths are often where weaker algorithms or deprecated parameter choices live. However, this file does not implement crypto algorithms; it wires up and provides the encryptor.

`web-crypto-function.service.ts` contains implementations of hash, PBKDF2/Argon2-ish flows, RSA encrypt/decrypt, AES key generation, and a number of test/example usages. This is the largest file and the place where most crypto operations are implemented or delegated to libraries. Relative to CWE-327, there potentially is direct risk of supporting weak/legacy hashing algorithms. `web-crypto-function.service.ts` contains explicit references to `sha1` and `md5`. If MD5 or SHA-1 is used for security-sensitive uses (password hashing, HMAC, signatures, integrity checks for untrusted data), this would be unsafe. Even if some uses are only for legacy support or tests, future developers may accidentally use MD5/SHA1 in security-critical contexts.


### [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

**Description:** The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

**Files Analyzed:** 
-  **[`extension-change-password.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/browser/src/auth/popup/change-password/extension-change-password.service.ts)**
-  **[`user-decryption-options.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/auth/src/common/services/user-decryption-options/user-decryption-options.service.ts)**
-  **[`login-email.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/auth/src/common/services/login-email/login-email.service.ts)**
-  **[`kdf-config.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/key-management/src/kdf-config.service.ts)**

`extension-change-password.service.ts` orchestrates the password-change workflow in the browser extension but does not directly process or store the raw master password. Instead, it delegates the entire operation to secure abstractions:

```
constructor(
  keyService: KeyService,
  masterPasswordApiService: MasterPasswordApiService,
  masterPasswordService: InternalMasterPasswordServiceAbstraction
) {
  super(keyService, masterPasswordApiService, masterPasswordService);
}
```
The design ensures that sensitive password material never touches this layer and is instead routed through internal secure services. As such, there is no credential exposure was. Password logic is abstracted behind secure services, and the module does not store any sensitive values.

`user-decryption-options.service.ts` manages the user's “decryption options” (e.g., whether vault unlock occurs via master password, biometric key, or device key). It stores metadata only — not password values. Sensitive user options are cleared on logout:

```
clearOn: ["logout"]
```
This prevents sensitive data from remaining in memory or persistent storage after a session ends. The service stores only metadata and never handles raw passwords.

`login-email.service.ts` manages login email state and login flow. It does not handle passwords or crypto keys. Authentication-sensitive work is delegated to AuthService and AccountService. The only persisted state in this module is:

```
private readonly loginEmailState: GlobalState<string>;
private readonly storedEmailState: GlobalState<string>;
```
These store email only, not password-derived secrets; there is no direct credential processing.

`kdf-config.service.ts` configures the Key Derivation Function (KDF) used to transform the master password into the master key. This module does not handle the password itself. Instead, it loads and stores KDF configuration parameters such as Argon2id and PBKDF2 settings:

```
import { Argon2KdfConfig, PBKDF2KdfConfig } from "./models/kdf-config";
```
The KDF configuration is securely stored and cleared upon logout. Only metadata is persisted; the raw master password never appears in this file. Thus, there is no vulnerability.

Overall, all examined modules demonstrate proper credential handling practices. Passwords, derived keys, and sensitive cryptographic material are abstracted behind secure services and KDF mechanisms. No component processed or stored sensitive values directly, and no CWE-522 weaknesses were identified.


### [CWE-532: Insertion of Sensitive Information Into Log Files](https://cwe.mitre.org/data/definitions/532.html)

**Description:** The product writes sensitive information to a log file.

**Files Analyzed:** 
-  **[`extension-change-password.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/browser/src/auth/popup/change-password/extension-change-password.service.ts)**
-  **[`user-decryption-options.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/auth/src/common/services/user-decryption-options/user-decryption-options.service.ts)**
-  **[`login-email.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/auth/src/common/services/login-email/login-email.service.ts)**
-  **[`kdf-config.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/key-management/src/kdf-config.service.ts)**

`extension-change-password.service.ts` contains no logging statements. Password operations occur silently through underlying services.

Similarly, `user-decryption-options.service.ts` contains no logging calls. Decryption options are deserialized and stored without console or diagnostic output.

`login-email.service.ts` contains no log statements. Email states and authentication flows do not produce logs and therefore cannot leak sensitive information.

`kdf-config.service.ts` also contains no logging calls. Even error messages are generic (e.g., “userId cannot be null”) and do not reveal cryptographic details or user-specific secrets.

Across all manually reviewed files, no logs were generated containing sensitive information. Bitwarden’s client code avoids logging in critical authentication and cryptographic modules, fully preventing CWE-532 risks.


###  [CWE-602: Client-Side Enforcement of Server Rules](https://cwe.mitre.org/data/definitions/602.html)

**Description:** The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

**Files Analyzed:** 

- **[`event-export.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event-export.service.ts)**
- **[`event.export.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event.export.ts)**
- **[`index.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/index.ts)**

After reviewing the listed files, no vulnerability was found. All authorization and access control checks occur **on the server**, not the client. The client only formats data *after the server has already validated permissions*. There is no business logic or privilege checking happening in the export module.


### [CWE-640: Weak Account Recovery Mechanism](https://cwe.mitre.org/data/definitions/640.html)

**Description:** The product contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak. 
  
**Files Analyzed:**

-  **[`api.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/services/api.service.ts)**
-  **[`emergency-access-trust.component.ts`](https://github.com/bitwarden/clients/blob/main/libs/key-management-ui/src/trust/emergency-access-trust.component.ts)**
-  **[`EmergencyAccessController.cs`](https://github.com/bitwarden/server/blob/main/src/Api/Auth/Controllers/EmergencyAccessController.cs)**
-  **[`EmergencyAccessService.cs`](https://github.com/bitwarden/server/blob/main/src/Core/Auth/Services/EmergencyAccess/EmergencyAccessService.cs)**

From `EmergencyAccessService.SendInviteAsync`, Token creation uses expiration but lacks single-use tracking:
```
tokenable.ExpirationDate = DateTime.UtcNow.AddHours(_globalSettings.OrganizationInviteExpirationHours);
```

From `EmergencyAccessController.Takeover`, Takeover does not require re-authentication:
```
await PasswordAsync(emergencyAccess, granteeUser, model);
```

The PasswordAsync method in EmergencyAccessService directly resets the vault owner’s password:
```
public async Task PasswordAsync(EmergencyAccess ea, User grantee, EmergencyAccessPasswordRequestModel model)
{
    user.PasswordHash = model.NewMasterPasswordHash;
    user.KeyEncrypted = model.NewKey;
}
```
There is no call to TOTP verification, WebAuthn, or any form of strong re-authentication.

Emergency Access uses a well-defined workflow involving invite, acceptance, confirmation, waiting period, and approval.Recovery tokens include identity binding (email + EmergencyAccessId) and have an expiration window.

Despite this, several weaknesses remain:

 - Takeover actions do not require recent re-authentication (no TOTP, WebAuthn, or password challenge).

 -  Recovery tokens are not single-use and are not tracked server-side after consumption.

 - No feature-specific rate limiting exists for recovery or takeover operations.

 - Critical actions are not logged for auditing.


The overall recovery design is strong, but missing second-layer protections. Adding re-auth, token invalidation, and detailed logging would significantly improve resistance to misuse.


### [CWE-642: External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

**Description:** The product stores security-critical state information about its users, or the product itself, in a location that is accessible to unauthorized actors.

**Files Analyzed:**

-  **[`api.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/services/api.service.ts)**
-  **[`emergency-access-trust.component.ts`](https://github.com/bitwarden/clients/blob/main/libs/key-management-ui/src/trust/emergency-access-trust.component.ts)**
-  **[`EmergencyAccessController.cs`](https://github.com/bitwarden/server/blob/main/src/Api/Auth/Controllers/EmergencyAccessController.cs)**
-  **[`EmergencyAccessService.cs`](https://github.com/bitwarden/server/blob/main/src/Core/Auth/Services/EmergencyAccess/EmergencyAccessService.cs)**

Emergency Access relies heavily on IDs and state transitions. If an attacker could manipulate those IDs, they could push the system into the wrong state. All Emergency Access mutations are routed through EmergencyAccessService.

The service validates:

- whether the caller is the grantor or grantee,
- whether the Emergency Access entry is in the correct status,
- whether the requested action is allowed from that state.

No alternate or direct repository paths were found that bypass these checks. This CWE is well-handled; ID-based state manipulation is not possible in the current design.


###  [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

**Description:** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

**Files Analyzed:**

-  **[`api.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/services/api.service.ts)**
-  **[`emergency-access-trust.component.ts`](https://github.com/bitwarden/clients/blob/main/libs/key-management-ui/src/trust/emergency-access-trust.component.ts)**
-  **[`EmergencyAccessController.cs`](https://github.com/bitwarden/server/blob/main/src/Api/Auth/Controllers/EmergencyAccessController.cs)**
-  **[`EmergencyAccessService.cs`](https://github.com/bitwarden/server/blob/main/src/Core/Auth/Services/EmergencyAccess/EmergencyAccessService.cs)**

- **[`event-export.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event-export.service.ts)**
- **[`event.export.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/event.export.ts)**
- **[`index.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/tools/event-export/index.ts)**

Exporting activity logs is a sensitive action. Currently, there is **no audit entry** generated when a user exports events. This does not create an immediate vulnerability, but it **reduces accountability** in environments that require full audit trails. The action `"User exported event logs"` should be logged on the server side.

Additionally, there are no audit logs in any part of Emergency Access. Examples of high-impact actions that generate no logs:
```
await ApproveAsync(...);
await RejectAsync(...);
await TakeoverAsync(...);
await PasswordAsync(...);
```

Even failed or invalid recovery attempts leave no trace.
There are missing logs for invite acceptance, recovery initiation, approvals/rejections, takeover attempts, password resets via recovery, and there is no correlation IDs or tracking for suspicious repeated actions. This is a significant gap. Recovery mechanisms require detailed auditing, and none exists in this module.

## Automated Code Review

The automated code review tools used for this project are Github CodeQL, Deepscan.io, and Semgrep CLI. We used these tool primarily to see if there were any other potential vulnerabilities that were not caught by the manual review for the entirety of the Bitwarden client repository.

### Deepscan.io 
Of the 192 issues found, only 6 were labeled high impact, so we focused on those. The remaining 186 were categorized as medium or low impact. With this, there were 2 additional CWEs that were not found by the manual review, as seen below:

#### [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)

**Description:** The product dereferences a pointer that it expects to be valid but is NULL. 

**Files Analyzed:**

- **[`collection-dialog.component.ts`](https://github.com/bitwarden/clients/blob/main/apps/web/src/app/admin-console/organizations/shared/components/collection-dialog/collection-dialog.component.ts)**
- **[`vault-v2.component.ts`](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/vault/app/vault/vault-v2.component.ts)**
- **[`desktop-autofill.service.ts`](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/autofill/services/desktop-autofill.service.ts)**
- **[`vault.component.ts`](https://github.com/bitwarden/clients/blob/main/apps/desktop/src/vault/app/vault-v3/vault.component.ts)**

`collection-dialog.component.ts` defines an Angular dialog used in Bitwarden’s web vault/admin console for:

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

And reported the following: 
> Variable 'nameParts' may have an undefined value originated from the expression 'collection.name' at line 528 . But its property is accessed at this point without null check.

The file is a large orchestration component, gathering data from multiple services, enabling user interaction, and saving/updating collections via API calls. However, it is not cryptographic; this part is fully UI and business logic.

`vault-v2.component.ts` is the main component behind the Vault screen in Bitwarden Desktop/Browser/Web. It controls:
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

And reported: 
> Variable 'collections' may have an undefined value originated from the expression 'this.vaultFilterComponent.collections' at line 973 . But its property is accessed at this point without null check.

However, this file essentially coordinates all vault UI behavior. It is not cryptography; it is almost entirely UI orchestration and application logic.

`desktop-autofill.service.ts` defines the Angular service DesktopAutofillService. Its main responsibilities are to initialize native autofill on macOS, synchronize credentials, listen to OS IPC events for FIDO2/passkey operations, covert requests/responses between IPC format and FIDO2 service format, and cleanup on destroy.

DeepScan.io highlighted the following lines of code:
```
      namespace: "autofill",
      command: "sync",
      params: {
        credentials: [...fido2Credentials, ...passwordCredentials],
      },
```

And reported the following two issues:
> Variable 'passwordCredentials' may be uninitialized if the false branch of the condition 'status.value.support.password' at line 108 is taken. But its property is accessed at this point without null check.

> Variable 'fido2Credentials' may be uninitialized if the false branch of the condition 'status.value.support.fido2' at line 126 is taken. But its property is accessed at this point without null check.

Relative to CWE-476, most potential null dereferences are guarded by checks and optional chaining. The only minor risk is status.value or status.value.support being null or undefined in sync(). If IPC returns a malformed object, accessing status.value.state.enabled or status.value.support.password could throw. It is low risk if the IPC is trustworthy.

`vault.component.ts` is an Angular component that represents the main interface for a vault in a password manager (likely Bitwarden, given the import paths). It manages the display, addition, editing, deletion, and interaction with various types of ciphers (passwords, cards, identities, secure notes, SSH keys) and associated metadata like collections, folders, and organizations. 

DeepScan.io highlighted the following lines of code:

```
      const collections = this.vaultFilterComponent.collections?.fullList.filter(
        (c) => c.id === this.activeFilter.selectedCollectionId,
      );
      if (collections.length > 0) {
        this.addOrganizationId = collections[0].organizationId;
```
And reported the following:
>Variable 'collections' may have an undefined value originated from the expression 'this.vaultFilterComponent.collections' at line 970 . But its property is accessed at this point without null check.

There is potential for NULL pointer dereference if any async data unexpectedly returns null, especially in cipher and activeUserId. Currently, the code mitigates most of these cases with checks, so actual risk is low but not zero.

#### [CWE-628: Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

**Description:** The product calls a function, procedure, or routine with arguments that are not correctly specified, leading to always-incorrect behavior and resultant weaknesses.

**Files Analyzed:**

- **[`default-organization.service.ts`](https://github.com/bitwarden/clients/blob/main/libs/common/src/admin-console/services/organization/default-organization.service.ts)**


`default-organization.service.spec.ts` is a unit test suite for the Angular service DefaultOrganizationService. Its main goals are to verify that the service behaves correctly in various scenarios, including handling null or empty states, updating organizations, and managing sponsorships.

DeepScan.io highlighted the following lines of code:

```
    if (input == null) {
      return undefined;
    }
    return Object.fromEntries(input?.map((i) => [i.id, i]));
  }
```
And reported the following:
>The first argument of 'Object.fromEntries()' should be an object. But an undefined value may be passed.

However, the tests verify correct argument handling and null safety. No function calls in the spec use incorrectly specified arguments. By asserting correct behavior, it helps prevent CWE-628 in the service usage.

### Github CodeQL
No issues were found with the files analyzed by manual review, and no additional vulnerabilities were detected with this tool.

### Semgrep CLI

Semgrep analyzed more than six thousand TypeScript, JavaScript, and HTML files and reported 18 issues, mainly in two categories:

#### [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

**Description:** The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

**Files Analyzed:**

- **[`build.js`](https://github.com/bitwarden/clients/blob/main/apps/desktop/desktop_native/build.js)**
- **[`after-pack.js`](https://github.com/bitwarden/clients/blob/main/apps/desktop/scripts/after-pack.js)**
- **[`optimize.js`](https://github.com/bitwarden/clients/blob/main/apps/web/scripts/optimize.js)**

Semgrep flagged several build and packaging scripts that use execSync() with values that could become unsafe if they were ever influenced by external input.

Example Code:
```
child_process.execSync(`npm run build -- ${targetArg}`, { stdio: "inherit" });
```
If targetArg or similar variables ever came from untrusted input, they could allow command injection. Right now these scripts are internal and used only in development builds, so the practical risk is low.

### [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

**Description:** The product uses user-supplied input to dynamically generate HTML content that is then displayed in a web page, but it does not properly sanitize or encode that content to prevent cross-site scripting (XSS) attacks.

**Files Analyzed:**
- Billing and subscription pages
- Billing history components
- Report components

Semgrep also warned about several HTML templates where dynamic values were placed directly into href attributes.

Example Code:
```
<a href="{{ i.url }}">View</a>
```

If the url or pdfUrl variables ever contained a value like javascript:alert(1), it could trigger XSS. In practice these URLs come from trusted internal sources, but Semgrep reports them because the pattern can be risky in general.

# Key Findings and Contributions

## Findings Summary
Using a scenario-based manual review, as well as automated review, we decided on/discovered the following CWEs:
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- CWE-79: Cross-Site Scripting (XSS)
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-522: Insufficiently Protected Credentials
- CWE-532: Insertion of Sensitive Information Into Log Files
- CWE-602: Client-Side Enforcement of Server Rules
- CWE-640: Weak Account Recovery Mechanism
- CWE-642: External Control of Critical State Data
- CWE-778: Insufficient Logging
- CWE-476: NULL Pointer Dereference
- CWE-628: Function Call with Incorrectly Specified Arguments

However, given our overall findings on the how much risk each CWE actually poses for Bitwarden, we identify the following notable CWEs that could be addressed to improve the overall security of the project:

- **[CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html):** 
  - Our findings show clear evidence that emergency access “takeover” can reset the vault owner’s master password without any strong re-authentication (no TOTP, no WebAuthn, no password challenge). Additionally:
    - Recovery tokens are not single-use
    - No rate limiting
    - No audit logs for critical recovery actions
    - Takeover flows are not tracked or monitored
    - Failed attempts leave no trace
  - This creates a high-impact, realistic misuse scenario.
If an attacker compromises a grantee’s email or token, they could take over a vault with no audit trail, which has high risk consequences.

- **[CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html):** 
  - We found multiple place, including event exports and all Emergency Access workflows, where there is no audit logging at all. This means:
    - Insider misuse is undetectable
    - Recovery-related attacks cannot be reconstructed
    - Organizations fail compliance requirements
  - In a real operational environment, missing logs can be as dangerous as missing access controls.

- **[CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html):**
  - We found actual references to SHA-1, MD5, AES-CBC, RSA-2048, AES-128, and other legacy encryptors. While the system may default to stronger settings, these risky algorithms still exist in the code, are callable, are used in some legacy paths, could be mistakenly used by developers, and/or could be misconfigured in deployments.
- **[CWE-327: Use of a Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html):**
  - Same as CWE-326.
- **[CWE-78: Improper Neutralization in OS Commands](https://cwe.mitre.org/data/definitions/78.html):**
  - This risk here is more moderate. Scripts using execSync() are vulnerable but only in development/build environments.

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

Using automated scanning tools also contributed to the project by revealing broader patterns and confirming that no unsafe credential-handling or logging behaviors existed across thousands of files. While automated tools identified minor issues in development scripts and template bindings, the deeper understanding came from manually tracing data flows and verifying that confidential information is never processed insecurely on the client side.

Additionally, working together to define CWEs, focus areas, and high-risk components reinforced the importance of team alignment and communication in security code reviews. Assigning specific components or functions to individual team members allowed for more thorough coverage and cross-validation of our findings.