# Authentication and Vault Management in Bitwarden Clients
![image](https://github.com/ysabum/Software-Assurance/blob/main/UC_Login_misuse.png)

## Description of Interaction
Use- Case:
The interaction is User Login: a customer (end-user) authenticates to Bitwarden in order to access and manage stored credentials. The system of interest is the Bitwarden client’s suite web application, browser extension, desktop app, and CLI—maintained in the bitwarden/clients repository. These clients coordinate with Bitwarden’s cloud APIs for account authentication and session issuance, while performing local cryptographic operations (e.g., key derivation and vault decryption). Clients may enforce organization or user policies such as two-step login, vault timeout, and auto-lock; the web client additionally supports phishing-resistant passkey/WebAuthn sign-in.

The primary actor is the Customer. Preconditions are that the user has an active Bitwarden account and the client can reach Bitwarden services over a TLS-protected connection. The trigger is the user selecting Log in in a Bitwarden client. In the main flow, the user chooses an authentication method—either the master-password path or a passkey (WebAuthn) flow. The client performs basic input checks and executes the appropriate authentication ceremony: for passwords, it derives keys locally using the configured KDF and submits the request; for passkeys, it completes a WebAuthn challenge/response. The service validates the attempt and issues a session, after which the client decrypts the vault keys and presents the unlocked vault. Postconditions are that the vault is open and subsequent access is controlled by the configured timeout/auto-lock policy, with sensitive actions potentially requiring re-authentication. Alternatives/Exceptions: if two-step login is enabled or mandated by policy, the client collects the second factor before the session is established; on any failure (invalid credentials or assertion, network error), the client remains locked and surfaces an error message.

## Description of the Misuse Cases :
1. Credential stuffing / brute force — attacker: “CredStormer” «misuser».
   Bots hammer the login with guesses or leaked combos. Mitigations: enable Two-Step Login (2FA, including FIDO2/WebAuthn) and enforce a strong KDF for the master secret (PBKDF2 or Argon2id with safe work-factors). Requirements: SR-L1 (KDF floor) and SR-L2 (authentication throttling with back-off or temporary lockout and velocity checks by account, device, and IP). Quick checks: if a user attempts to save a KDF below the floor, then the client blocks the change and shows guidance; if an attacker scripts many failures (for example, 1,000 per minute), then throttling or lockout occurs and an audit event is recorded.

2. Phishing to a fake origin — attacker: “PhishPrince” «misuser».
   A look-alike site tricks users into submitting credentials or 2FA codes. Mitigations: support Passkey/WebAuthn login (origin-bound, phishing-resistant) and require New-Device Verification before issuing a long-lived session on first-seen devices. Requirements: SR-P1 (origin-bound authentication) and SR-P2 (new-device check). Quick checks: if a WebAuthn assertion is replayed on a non-Bitwarden origin, then verification fails; if a sign-in occurs from a fresh device, then a verification step is required, and a trusted device can bypass it on subsequent logins.

3. Session hijacking / replay — attacker: “SessionSnatcher” «misuser».
   The adversary steals or reuses session/refresh tokens or abuses long idle unlocks. Mitigations: enforce Auto-Lock or Vault Timeout and implement Session Hardening (Secure/HttpOnly/SameSite cookies where applicable, short token lifetimes, rotation on authentication events, and a user-initiated Deauthorize-all-sessions control). Requirements: SR-S1 (session hygiene plus deauthorization) and SR-S2 (timeout and re-authentication for sensitive tasks). Quick checks: if the user triggers deauthorize sessions, then online clients log out promptly and offline clients log out on reconnect; if the application is idle beyond policy, then the vault locks; if the user attempts an export or email change, then re-authentication is required.


## Security Requirements and Features
### Security Requirements:


1. SR-AUTH-1: Support master-password and WebAuthn passkey login with strict origin binding.

2. SR-AUTH-2: Provide Two-Step Login (2FA) options and allow org policy to require them.

3. SR-AUTH-2: Provide Two-Step Login (2FA) options and allow org policy to require them.

4. SR-AUTH-3: Require new-device verification before issuing any persistent session.

5. SR-AUTH-4: Enforce progressive throttling and temporary lockout after repeated failures (per account/device/IP).

6. SR-KDF-1: Derive the master key client-side using PBKDF2 or Argon2id; never send the master password.

7. SR-KDF-2: Enforce minimum KDF parameters and block saving values below the floor.

8. SR-SESSION-1: Use secure session hygiene (Secure/HttpOnly/SameSite where applicable) with short-lived, rotating tokens.

9. SR-SESSION-2: Implement vault timeout/auto-lock on inactivity and on app restart; cap max session lifetime.

10. SR-SESSION-3: Provide Deauthorize all sessions to remotely invalidate active logins.

11. SR-REAUTH-1: Require re-authentication for sensitive actions (export, email change, 2FA/KDF changes).

12. SR-INPUT-1: Validate and normalize login inputs (including Unicode normalization) to reduce spoofing.

13. SR-USABILITY-1: Nudge users to enable 2FA and to raise KDF strength with clear UI guidance.

### Bitwarden features that cover these 
Bitwarden, as an OSS project, already implements several strong features that align with these requirements:

1. Passkey / WebAuthn login (web vault) – how to sign in with a passkey, and what happens if the passkey can (or can’t) decrypt your vault.(https://https://bitwarden.com/help/login-with-passkeys/) 

2. Two-Step Login (2FA) options – overview of all methods; setup guides (incl. FIDO2/WebAuthn security keys and authenticator apps). (https://bitwarden.com/help/setup-two-step-login/)

3. KDF algorithms & minimums – change KDF to Argon2id or increase PBKDF2 iterations (≥ the current floor); note that saving changes logs you out everywhere. (https://bitwarden.com/help/kdf-algorithms/)
4. Vault timeout / auto-lock – configure lock vs. logout after inactivity in web, extension, and desktop clients.(https://bitwarden.com/help/vault-timeout/) 

5. New-device login protection – one-time email verification when signing in from a first-seen device (especially if 2FA isn’t enabled).
 
6. Deauthorize all sessions (“panic button”) – Bitwarden’s guidance to force logout on all devices from the web vault.(https://bitwarden.com/help/security-faqs/)

7. URI match detection (autofill safety) – tighten match rules (Exact/Host/Base Domain) to reduce autofill on look-alike phishing sites. (https://bitwarden.com/help/uri-match-detection/)
   
## OSS Project Documentation: Security-Related Configuration and Installation Issues

1. Official origins only (anti-phishing). Users should sign in only at the official Bitwarden web vault domain (or your self-host origin) and install extensions/desktops from the official publishers. Document the exact URLs you approve to prevent origin mix-ups during login.

2. Passkey/WebAuthn availability. Passkey login is supported in the web app; other clients may lag. Note that some authenticators can decrypt the vault via PRF while others still require the master password after login. Set expectations per platform.

3. Two-Step Login (2FA) & backup. Require a strong second factor (FIDO2/WebAuthn key, TOTP, Duo, etc.) and make users enroll a backup method so they don’t lock themselves out.

4. New-device verification. If 2FA is not enabled, first-seen devices should trigger a one-time verification before granting a persistent session. Advise users to “trust” only personal devices.

5. KDF parameters (client-side key derivation). Use Argon2id (preferred) or PBKDF2 with a safe floor. Explain that changing KDF re-authenticates and logs out other devices, so schedule changes and keep 2FA ready.

6. Vault timeout / auto-lock. Avoid “Never” for timeouts. Enforce lock or logout after inactivity and on app restart to reduce session-theft exposure, especially on shared machines.

7. Remote de-auth (“panic button”). Teach users to use Deauthorize Sessions from the web vault after device loss or suspected compromise. Note that offline clients log out on next reconnect.

8. Browser extension safety.
a) Use precise URI match rules (Exact/Host/Base Domain) to curb autofill on look-alike sites.
b) After extension updates, browsers may request new permissions—verify the publisher/ID before approving.

9. Desktop integrity & secrets at rest. Verify signed installers; prefer storing session secrets in the OS keychain where available. If biometric/PIN unlock is enabled, document policy (e.g., disable on shared systems).

10. CLI hygiene. Avoid persisting session tokens or master passwords in shell history. If you temporarily set environment variables (e.g., BW_SESSION), export them in the current shell only and clear them after use.

11. Self-hosted deployments. Use a single canonical origin with valid TLS; mismatched subdomains or CORS misconfigurations lead to failed WebAuthn ceremonies and confusing login errors.

12. Error messaging & logging. Ensure login errors remain generic (no user enumeration) and that authentication events (success/failure, factor used, device) are recorded without logging secrets.

13. Feature gaps to call out (FYI). Some mitigations—detailed lockout thresholds, cookie flags/rotation internals, device fingerprinting, advanced alerting—are server-side or enterprise tier; keep them as requirements to verify, not assumptions.

While Bitwarden’s documentation is thorough (https://bitwarden.com/help/ ), several security-related configuration and installation mismatches exist in the OSS clients:


## OSS Project Documentation: Security-Related Configuration & Installation Issues

1. Official origins only (anti-phishing): restrict login to approved domains and official stores.
2. Passkey/WebAuthn availability: web vault supports passkeys; document PRF behavior and platform limits.
3. Two-Step Login (2FA) with a backup method is required.
4. New-device verification before issuing persistent sessions.
5. KDF parameters: Argon2id (preferred) or PBKDF2 at/above the floor; changing KDF logs out other sessions.
6. Vault timeout / auto-lock on inactivity and on app restart.
7. Remote “Deauthorize Sessions” for suspected compromise; offline clients drop on reconnect.
8. Extension safety: precise URI match rules; verify any permission prompts after updates.
9. Desktop integrity: verify signed installers; store secrets in the OS keychain; policy on biometric/PIN unlock.
10. CLI hygiene: do not persist session tokens or the master password in shell history.
11. Self-host: one canonical origin with valid TLS; avoid CORS/origin mismatches.
12. Error handling & logging: generic messages; auth events logged without secrets.
13. Gaps to verify: server lockout thresholds, cookie/rotation details, and enterprise-only alerts.

```bash

export SSH_AUTH_SOCK=/home/<user>/.bitwarden-ssh-agent.sock.

```

Overall Assessment: I learned to iterate between use and misuse cases and turn each threat into a concrete, testable requirement, keeping a clean chain from misuser to misuse to mitigation to SR and to the Bitwarden feature.
Digging into passkeys clarified origin binding and when PRF-capable authenticators can unlock the vault, while comparing Argon2id and PBKDF2 showed why enforcing minimum KDF work factors matters.
Session hygiene stood out—timeouts, token rotation, and “deauthorize sessions” directly reduce hijacking risk, and weak timeout choices can undo strong crypto.
Building the diagram in diagrams.net and the Markdown checklist in VS Code made the design easy to review, and separating client capabilities from server or policy controls taught me to flag gaps as requirements to verify, not assumptions.


## Reflection
**Sai Santhoshi Arcot:** This project taught me to turn threats into specific, testable requirements and keep tight traceability from misuser to misuse to mitigation and into Bitwarden’s actual client features. The diagrams and Markdown checklist made the design easy to review, and comparing it with OSS docs highlighted real gaps (like lockout thresholds and session details) to verify. Overall, I finished with a practical, defensible login model and a clear list of next steps for hardening.

