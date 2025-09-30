# Requirements for Software Security Engineering

## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)

## Hypothetical Operation Environment
Our hypothetical operation environment is for a national retail bank, where the company is developing a secure online banking application that allows customers to manage their accounts, transfer funds, pay bills, and apply for loans. The company expects to integrate a security tool like Bitwarden to protect credentials and sensitive financial operations for both the employees and customers.

## Essential Interactions
1. User Logon to Account
2. User Accesses and Retrieves Secret from Secrets Manager
3. Emergency Contact Access
4. Audit Security

# [2. User Accesses and Retrieves Secret from Secrets Manager](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Secrets_Manager/SecretsManager.md?plain=1)
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
   
# [3. Emergency Contact Access](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Emergency_Contact/EmergencyContact.md)
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

1. **Impersonation Attack:** A malicious actor pretends to be the Trusted Contact and submits a request for access.

2. **Manipulation of Customer Approval:** An attacker socially engineers or coerces the Bank Customer to approve a fraudulent request.

3. **Notification Bypass:** An attacker intercepts or disables emergency access notifications so the Bank Customer is unaware of the request.

4. **Early Access Exploit:** An attacker manipulates the system to bypass or shorten the waiting period, gaining vault access before intended.

5. **Insider Misuse:** A bank administrator with legitimate Trusted Contact privileges abuses their access for unauthorized purposes.

## Security Requirements and Features
### Required:
From these misuse scenarios, the following security requirements are derived:

1. **Strong Identity Verification:** The Trusted Contact must undergo multi-factor identity checks before being accepted.

2. **Multi-Channel Notifications:** Customers should be notified across multiple channels (e.g., email, SMS, push notification) to reduce the silent attacks.

3. **Enforced Waiting Period:** A mandatory waiting period should be non-configurable and tamper-resistant, preventing early access exploits.

4. **Emergency Access Revocation:** Customers should have the ability to revoke Trusted Contact permissions at any time.

5. **Access Limitation Controls:** Vault access should allow configurable scoping (e.g., only certain items).

6. **Comprehensive Audit Logging:** Every emergency access event must be logged, with immutable audit trails for customer and organizational review.

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

3. Emergency Access: (https://bitwarden.com/help/emergency-access/#trusted-emergency-contacts) Built-in ability to configure trusted emergency contacts with waiting periods.
4. Audit Logs (Enterprise): Organizational accounts support event logging and monitoring.(https://bitwarden.com/help/event-logs/) Bitwarden allows organizations to access, inspect, or export logs for a given time frame; only 367 days worth of data may be viewed at a time. Events are captured at both the Bitwarden client and server, with most events occurring at the client. While server event capture is instantaneous and quickly processed, clients push event data to the server every 60 seconds, so you may observe small delays in the reporting of recent events. 

5. Revocation: Customers may revoke View access anytime. For Takeover, revocation requires resetting the master password after a takeover occurs.

**References:** 
  1. Help Document: https://bitwarden.com/help/emergency-access/#use-emergency-access
  2. Emergency Access feature: https://github.com/bitwarden/server/issues/28


# [4. Audit Security](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Audit_Security/Audit_Security.md?plain=1)
![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Requirements/Audit_Security/Usecase%201.jpeg?raw=true)

## Description of the Use Case Scenario
The Bank Security Team uses Bitwarden to keep track of important activities.  
Here’s how it works:
1. Bitwarden creates logs for logins, secret retrievals, and secret rotations.  
2. The Security Team opens the Bitwarden Admin Console.  
3. They check the logs and enforce rules like requiring MFA, blocking certain IPs, or stopping copy/export of data.  
4. If they find something unusual, they take action such as revoking access or rotating secrets.  

This helps the bank monitor user actions and react quickly to any security issues.


## Description of the Misuse Cases
A malicious ex-developer might try to misuse the system in these ways:
- **Delete or change logs** → stopped by **immutable server-side log storage**.  
- **Read logs to steal metadata** (like usernames or IPs) → reduced by **role-based admin permissions**.  
- **Use a stolen account to bypass policies** → blocked by **mandatory MFA and policy enforcement**.  
- **Flood the system with fake log entries** → detected by **alerting and anomaly detection** tools.  


## Security Requirements and Features
### Required:
To stay secure, the system needs:
- Logs that cannot be changed or deleted.  
- Admin permissions so only the right people can see or use logs.  
- Mandatory MFA and policy rules that even stolen accounts can’t bypass.  
- Alerts and detection for strange behavior like log flooding.  
- Quick ways to revoke accounts and rotate secrets when needed.  


### What Bitwarden Provides:
Bitwarden already offers many helpful features:
- **Audit logs & event monitoring** (enterprise accounts).  
- **Zero-knowledge encryption** so only users can see their secrets.  
- **Policy enforcement** like MFA, IP restrictions, password rules, and export controls.  
- **Role-based access** to control what admins can see.  
- **Revocation tools** to remove access and rotate secrets fast.  

Some advanced features (like stronger anomaly detection or full immutable storage) may need external tools or enterprise versions.

# OSS Project Documentation: Security-Related Configuration and Installation Issues
All documentation related to Bitwarden is available [here](https://bitwarden.com/help/); the documentation is fairly thorough. However, listed below is one notable security-related configuration and installation issue that we were able to find that does not properly match with the documentation:  
- **Bitwarden SSH Agent Defaults to Improper SSH Socket Location [#13099](https://github.com/bitwarden/clients/issues/13099).** Particularly, the documentation for https://bitwarden.com/help/ssh-agent/ is wrong; it claims the Bitwarden SSH Agent socket location on Linux is:
    ```
    export SSH_AUTH_SOCK=/Users/<user>/.bitwarden-ssh-agent.sock
    ```
    However its actual location is `/home/<user>/.bitwarden-ssh-agent.sock`.

Specific documentation for audit logs and event monitoring can be found [here](https://bitwarden.com/help/event-logs/). However, some configuration and installation issues in the OSS version do not fully align with the documentation. For example:

- **Audit Log Availability Limitations:**  
  Bitwarden OSS clients do not include enterprise-grade event logs. The documentation often assumes organizational accounts, but OSS users will not see the same level of audit detail. https://bitwarden.com/help/event-logs/

- **Delay in Client-to-Server Log Sync:**  
  As noted in the official docs, server events are captured immediately, but client events are only synced every 60 seconds. This delay is not always clearly emphasized, which may lead to confusion when testing near real-time monitoring.
  https://bitwarden.com/help/event-logs/#client-events

- **Immutable Log Storage Not Native:**  
  While the docs discuss audit logs, OSS installs do not provide built-in immutability or WORM (Write Once, Read Many) protections. Administrators must configure external log management systems (e.g., Splunk, or SIEM tools) to achieve tamper-proof storage. https://bitwarden.com/help/event-logs/

- **Role-Based Permissions Scope:**  
  Role-based access is explained well in the documentation, but OSS versions provide only limited granularity compared to the enterprise edition. This mismatch can create gaps if teams rely solely on OSS for fine-grained log visibility.
  https://bitwarden.com/help/user-types-access-control/

Other Bitwarden Feature Gaps:

1. Advanced mitigations such as multi-channel notifications, biometric verification, device fingerprinting, and granular vault scoping are not available by default in OSS clients.
2. Some enterprise-level features (audit logs, event monitoring) are limited to organizational accounts.

# Reflection
This assignment helped showcase how integral use cases are in identifying the critical interactions of a software system with its environment. The process of creating these use cases clarified how the Bitwarden system is intended to be used with our hypothetical operation environment and helped us uncover security risks tied to those interactions. For example, Emergency Access can be viewed mainly as a helpful recovery option, but mapping out misuse cases showed how many attack angles exist and how easily a feature can turn into a vulnerability if not designed carefully. By looking at how a malicious actor might try to misuse the system, we saw why features like MFA, permissions, and security logs are so important. By connecting our misuse case analysis with Bitwarden’s documentation and features, we saw how theory applies in practice. Overall, we learned to think not only about how a system should work, but also how it could be misused, and we gained a stronger ability to think critically about security and to balance usability with protection.
