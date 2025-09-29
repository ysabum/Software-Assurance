# Emergency Contact Access
![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Emergency_Contact/emergencyContact.drawio.png?raw=true)

## Description of the Use Case Scenario
The Emergency Access feature in Bitwarden allows a Bank Customer to designate a Trusted Contact (e.g., a family member or bank administrator) to request access to their vault in emergencies, such as when the customer forgets their master password or faces medical incapacity. The feature is available to premium users or members of paid organizations (Families, Teams, Enterprise), while anyone with a Bitwarden account can be designated as a trusted emergency contact.

The workflow follows four main steps:

1. The Bank Customer configures a Trusted Contact in their Bitwarden settings.

2. The Trusted Contact submits an emergency access request.

3. The Bank Customer is notified and can approve or deny the request within a waiting period.

4. If approved or if the waiting period expires without denial—the Trusted Contact gains access to the vault.

This ensures essential credentials remain accessible in emergencies while preserving user control and oversight.

## Description of the Misuse Cases
Despite its value, the Emergency Access feature introduces potential threats. Some key misuse scenarios are:

1. Impersonation Attack: A malicious actor pretends to be the Trusted Contact and submits a request for access.

2. Manipulation of Customer Approval: An attacker socially engineers or coerces the Bank Customer to approve a fraudulent request.

3. Notification Bypass: An attacker intercepts or disables emergency access notifications so the Bank Customer is unaware of the request.

4. Early Access Exploit: An attacker manipulates the system to bypass or shorten the waiting period, gaining vault access before intended.

5. Insider Misuse: A bank administrator with legitimate Trusted Contact privileges abuses their access for unauthorized purposes.

## Security Requirements and Features
### Required:
From these misuse scenarios, the following security requirements are derived:

1. Strong Identity Verification: The Trusted Contact must undergo multi-factor identity checks before being accepted.

2. Multi-Channel Notifications: Customers should be notified across multiple channels (e.g., email, SMS, push notification) to reduce the silent attacks.

3. Enforced Waiting Period: A mandatory waiting period should be non-configurable and tamper-resistant, preventing early access exploits.

4. Emergency Access Revocation: Customers should have the ability to revoke Trusted Contact permissions at any time.

5. Access Limitation Controls: Vault access should allow configurable scoping (e.g., only certain items).

6. Comprehensive Audit Logging: Every emergency access event must be logged, with immutable audit trails for customer and organizational review.

### What Bitwarden Offers:
Bitwarden, as an OSS project, already implements several strong features that align with these requirements:

1. Zero-Knowledge Encryption: (https://bitwarden.com/resources/zero-knowledge-encryption/) Specifically from their documentation, Bitwarden integrates zero-knowledge encryption through:
   1. **Comprehensive end-to-end encryption:** uses AES-256 to secure data every step of the way, from creation through transit to cloud storage.
   2. **Exclusive user-controlled master passwords:** uses strong, locally-held master passwords, with zero access by Bitwarden.
   3. **Secrets manager:** applies Zero-Knowledge Encryption to developer secrets, API keys, and CI/CD credentials.
   4. **Secure credential sharing tools:** provides encrypted, controlled access through [Bitwarden Send](https://bitwarden.com/blog/bitwarden-send-how-it-works/) and team-based collections, where only the user and intended recipients are able to decrypt the data.
   5. **Robust emergency access capabilities:** securely facilitates business continuity through encrypted, designated recovery access processes. This is key as without a structured recovery mechanism, your data cannot be recovered.
   6. **Transparent, auditable [open source](https://bitwarden.com/blog/why-open-source-delivers-transparency-and-security-for-enterprises/) architecture:** ensures continual verification and validation of its encryption methodology.
   7. **Self-hosting option for data sovereignty:** offers full control over encrypted data for organizations requiring the most stringent security controls, taking zero-knowledge even a step further by limiting data available outside their installation.

2. Multi-Factor Authentication (MFA): (https://bitwarden.com/help/setup-two-step-login/) Bitwarden utilizes various forms of two-factor authentication (2FA), such as:
   1. FIDO2 WebAuthn credentials (e.g., hardware keys like YubiKeys and Google Titan)
   2. Authenticator app (e.g., Bitwarden Authenticator)
   3. Email
   4. Duo Security with Duo Push, SMS, phone call, and security keys
   5. YubiKey OTP (any 4/5 series device or YubiKey NEO/NFC)

3. Emergency Access: ( https://bitwarden.com/help/emergency-access/#trusted-emergency-contacts )Built-in ability to configure trusted emergency contacts with waiting periods.
4. Audit Logs (Enterprise): Organizational accounts support event logging and monitoring.(https://bitwarden.com/help/event-logs/) Bitwarden allows organizations to access, inspect, or export logs for a given time frame; only 367 days worth of data may be viewed at a time. Events are captured at both the Bitwarden client and server, with most events occurring at the client. While server event capture is instantaneous and quickly processed, clients push event data to the server every 60 seconds, so you may observe small delays in the reporting of recent events. 

5. Revocation: Customers may revoke View access anytime. For Takeover, revocation requires resetting the master password after a takeover occurs.
   
## OSS Project Documentation: Security-Related Configuration and Installation Issues

While Bitwarden’s documentation is thorough (https://bitwarden.com/help/ ), several security-related configuration and installation mismatches exist in the OSS clients:
    ```
    export SSH_AUTH_SOCK=/Users/<user>/.bitwarden-ssh-agent.sock
    ```
    However its actual location is `/home/<user>/.bitwarden-ssh-agent.sock`.

Feature Gaps:

1. Advanced mitigations such as multi-channel notifications, biometric verification, device fingerprinting, and granular vault scoping are not available by default in OSS clients.

2. Some enterprise-level features (audit logs, event monitoring) are limited to organizational accounts.

Overall Assessment:
Bitwarden’s OSS clients align closely with the derived security requirements, addressing most critical threats through strong encryption, enforced waiting periods, identity verification, and revocation features. However, organizations with higher risk profiles (e.g., national banks) should complement Bitwarden with additional operational and environmental controls, especially for notification integrity and granular access restrictions.
   
## Reflection
**Swetha Ulli:** This assignment helped me see the importance of looking at a feature not just for its intended use but also for how it could be misused. At first, I viewed Emergency Access mainly as a helpful recovery option, but mapping out misuse cases showed me how many attack angles exist and how easily a feature can turn into a vulnerability if not designed carefully. The most useful part for me was connecting our misuse case analysis with Bitwarden’s documentation and features, which showed how theory applies in practice. Overall, I gained a stronger ability to think critically about security and to balance usability with protection.
