# User Accesses and Retrieves Secret from Secrets Manager
![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Secrets_Manager/SecretsManager.drawio.png?raw=true)

## Description of the Use Case Scenario
The user (a developer for the banking application) logs in to Bitwarden and accesses the secret manager to retrieve a secret. Bitwarden's secret manager can be used by enterprises (a banking application for a national retail bank in this case) to store important data in a centralized space, such as database credentials, API token for payment processors, etc. This data is encrypted.  

## Description of the Misuse Cases
1. The attacker, a malicious lower-level ex-employee, attempts to steal the user's login credentials using a phishing attack, potentially using a fake email or SMS message pretending to be from the banking company as a vector. To mitigate this, multi-factor authentication (MFA), such as an authenticator app, SMS codes, biometrics, etc., can prevent the attacker from being able to fully logon to Bitwarden.
2. When this fails, the attacker instead uses their previous credentials to logon, and succeeds. However, when attempting to then access the secrets manager, they are then mitigated by role-based access restrictions and zero-knowledge encryption. With role-based access, users who are not a part of a certain group (like an admin, owner, or custom group) cannot access certain information. In this case, the lower-level ex-employee did not have high enough clearance to access the secrets manager. With zero-knowledge encryption, even if the attack does manage to access the secrets manager, without possession of a master key (or password), the data in the secrets manager will remain encrypted.
3. *What if the attacker did have the master key?* Device or IP restrictions can be enacted to prevent employees who are not using a company-issued device and/or the secure company IP address from accessing the secrets manager, regardless of whether or not they possess the master key. In the worst case scenario, if the attacker *does* possess the master key and *does* possess the company device and/or uses IP spoofing to access the secrets manager and retrieve a secret, an administator can use built-in audit logging (where every retrieval of a secret is logged) to detect suspicious activity and revoke the session, disable the attacker's account, or force credential rotations. To follow up on this, admins can enforce enterprise policies, where “copy to clipboard” or “export” features are disabled and where secrets can be used is restricted, making it harder for an attacker to exfiltrate data even after viewing it. Automated secrets rotation can also invalidate stolen secrets and replace them quickly.

## Security Requirements and Features
### Required:
1. Multi-Factor Authentication
2. Role-Based Access
3. Zero-Knowledge Encryption
4. Device/IP Restriction
5. Secrets Rotation
6. Audit Logging/Events Monitoring
7. Enterprise Policies

### What Bitwarden Offers:
1. **Multi-Factor Authentication:** [Yes.](https://bitwarden.com/help/setup-two-step-login/) Bitwarden utilizes various forms of two-factor authentication (2FA), such as:
    1. FIDO2 WebAuthn credentials (e.g., hardware keys like YubiKeys and Google Titan)
    2. Authenticator app (e.g., Bitwarden Authenticator)
    3. Email
    4. Duo Security with Duo Push, SMS, phone call, and security keys
    5. YubiKey OTP (any 4/5 series device or YubiKey NEO/NFC)
  
    It should be noted that all of these 2FA options are for individuals, except Duo Security, which is for both an individual user or an organization.
2. **Role-Based Access:** [Yes.](https://bitwarden.com/help/user-types-access-control/) You can define users, admins, owners, and custom groups. 
3. **Zero-Knowledge Encryption:** [Yes.](https://bitwarden.com/resources/zero-knowledge-encryption/) Specifically from their documentation, Bitwarden integrates zero-knowledge encryption through:
    1. **Comprehensive end-to-end encryption:** uses AES-256 to secure data every step of the way, from creation through transit to cloud storage.
    2. **Exclusive user-controlled master passwords:** uses strong, locally-held master passwords, with zero access by Bitwarden.
    3. **Secrets manager:** applies Zero-Knowledge Encryption to developer secrets, API keys, and CI/CD credentials.
    4. **Secure credential sharing tools:** provides encrypted, controlled access through [Bitwarden Send](https://bitwarden.com/blog/bitwarden-send-how-it-works/) and team-based collections, where only the user and intended recipients are able to decrypt the data.
    5. **Robust emergency access capabilities:** securely facilitates business continuity through encrypted, designated recovery access processes. This is key as without a structured recovery mechanism, your data cannot be recovered.
    6. **Transparent, auditable [open source](https://bitwarden.com/blog/why-open-source-delivers-transparency-and-security-for-enterprises/) architecture:** ensures continual verification and validation of its encryption methodology.
    7. **Self-hosting option for data sovereignty:** offers full control over encrypted data for organizations requiring the most stringent security controls, taking zero-knowledge even a step further by limiting data available outside their installation.
4. **Device/IP Restriction:** [Sort of.](https://community.bitwarden.com/t/restrict-account-access-to-certain-countries-ip-ranges/180) Bitwarden allows individuals and organizations to only allow logins/vault or secrets manager access from a certain IP, which works if the organization has a static IP. However, Bitwarden does **not** have a blacklist feature to prevent users from a certain IP/IP range/country from accessing confidential information.
7. **Secrets Rotation:** [Yes, ](https://bitwarden.com/help/secrets-manager-overview/)[though it is not an automated process.](https://bitwarden.com/help/account-encryption-key/)
8. **Audit Logging/Events Monitoring:** [Yes.](https://bitwarden.com/help/event-logs/) Bitwarden allows organizations to access, inspect, or export logs for a given time frame; only 367 days worth of data may be viewed at a time. Events are captured at both the Bitwarden client and server, with most events occurring at the client. While server event capture is instantaneous and quickly processed, clients push event data to the server every 60 seconds, so you may observe small delays in the reporting of recent events. 
9. **Enterprise Policies:** [Yes.](https://bitwarden.com/help/policies/) Bitwarden allows organizations to enforce security rules for all users, such as master password requirements, remove unlock with pin, remove export vault data, remove Send options, etc.
   
## OSS Project Documentation: Security-Related Configuration and Installation Issues
All documentation related to Bitwarden is available [here](https://bitwarden.com/help/); the documentation is fairly thorough. However, listed below are some security-related configuration and installation issues that we were able to find that do not properly match with the documentation:  
1. Bitwarden SSH Agent Defaults to Improper SSH Socket Location [#13099](https://github.com/bitwarden/clients/issues/13099). Particularly, the documentation for https://bitwarden.com/help/ssh-agent/ is wrong; it claims the Bitwarden SSH Agent socket location on Linux is:
    ```
    export SSH_AUTH_SOCK=/Users/<user>/.bitwarden-ssh-agent.sock
    ```
    However its actual location is `/home/<user>/.bitwarden-ssh-agent.sock`.
   
## Reflection
**Henny Omoregie:** As a group, we initially had difficulties with coming prepared to the instructor meeting to discuss this assignment. We typically have our team meetings about 30 minutes before the instructor meeting, since that's the only time that works for all of us (on the weekdays, that is). We scheduled this meeting to specifically discuss what essential interactions there were of Bitwarden with its environment of operation, but in doing so, while all of us had a good idea of what the use cases would be for our software, we hadn't actually done any diagramming yet, so there was only so much feedback we could get from our professor. To make sure we were all on the same page, we then scheduled a 2 progress meetings the following Saturday and Sunday, which was very helpful. In the future, I believe it would be more useful for us to have an additional team meeting on the weekends if possible; we could use that time for brainstorming, while our Wednesday meeting time could be used to check progress on the assignment(s).
