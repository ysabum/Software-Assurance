# Assurance Case for Software Security Engineering

## Top Claim 1 
[Bitwarden's Secrets Manager minimizes unauthorized access to secrets.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Secrets/Secrets.md)

![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Secrets/Secrets.drawio.png?raw=true)

## Top Claim 2
[Bitwarden audit logs minimize tampering and unauthorized alteration.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Audit_Logs/README.md)

![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Audit_Logs/Assurance_case.drawio.png)

This assurance case argues that Bitwarden maintains trustworthy audit logs by ensuring integrity, availability, and restricted access.  
Security mechanisms such as cryptographic signing, replication, **backup enforcement**, and **role-based access control** collectively ensure that audit logs cannot be modified or deleted without detection.

## Top Claim 3
[Bitwarden client applications adequately protect user vault secrets from unauthorized disclosure during local storage and synchronization.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Vault_Confidentiality/Vault_Confidentiality.md)

![Vault Confidentiality Diagram](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Vault_Confidentiality/Bitwarden_AssuranceCase_C1.png?raw=true)

This claim demonstrates that Bitwarden’s client applications maintain strong confidentiality through end-to-end encryption, secure key handling, encrypted synchronization, and enforced vault timeouts. Together these controls ensure that even if local devices, caches, or network channels are exposed vault data remains inaccessible to unauthorized entities.

### AI Usage

We used targeted prompts to refine claim phrasing, generate realistic rebuttals, and enforce noun-phrase evidence across cases. All AI output was reviewed and validated against Bitwarden documentation and code.

## Top Claim 4

[Bitwarden keeps emergency contact access secure.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Emergency_access/emergency_access.md)

![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Emergency_access/assuranceCaseEA.drawio.png?raw=true)

This claim argues that the Emergency Access feature in Bitwarden ensures only authorized and verified contacts can access vault data under controlled and auditable conditions. Security mechanisms such as encryption, MFA, waiting period enforcement, and event logging collectively support this assurance.

### AI Usage

#### AI Prompt Used
> “You are an expert software assurance engineer. Your job is to refine the phrasing of assurance claims for the Bitwarden Emergency Access feature. Each claim must include an entity, a security property, and a measurable value, and avoid phrasing about implementation methods.”

#### Usefulness Reflection
This prompt helped reframe the team’s thinking from “Bitwarden uses AES encryption” to “Bitwarden ensures vault data remains confidential.”  
It improved the logical precision of our claims and focused the assurance argument on security *outcomes* rather than technical *means*. This approach made the assurance case more persuasive and aligned with stakeholder expectations.


## Alignment and Gaps with Bitwarden
### Top Claim 1: Bitwarden's Secrets Manager minimizes unauthorized access to secrets.
#### Evidence E1: Bitwarden's Encryption Protocols
Documentation for Bitwarden's Encryption Protocols can be found [here](https://bitwarden.com/help/what-encryption-is-used/). This documentation describes the encryption protocols used by Bitwarden to encrypt secrets; the protocols include AES-256-CBC and PBKDF2-HMAC-SHA256. These protocols are chosen to provide strong encryption and to be compatible with the latest standards. All vault data (including secrets) is strongly encrypted by Bitwarden before being stored anywhere. Bitwarden provides a backup option to encrypt the secrets before uploading them to the cloud.  
  
**Gap:** Overall, there are no manjor gaps between the evidence identified for this claim and the documentation provided by Bitwarden. However, Bitwarden does not offer ECC (Elliptic Curve Cryptography) implementation, which could offer higher efficiency and security margin.

#### Evidence E2: Bitwarden's User Type Access Controls
Documentation for Bitwarden's User Type Access Controls can be found [here](https://bitwarden.com/help/managing-users/) and [here](https://bitwarden.com/help/user-types-access-control/). This documentation describes the different user types and their access controls in Bitwarden. Bitwarden provides four main user types: user, admin, owner, and custom. Whether a member can access the Secrets Manager depends on their user type and their access controls.  
  
**Gap:** Overall, there are no major gaps between the evidence identified for this claim and the documentation provided by Bitwarden. However, role review automation is not currently documented, so permissions may need periodic manual review.

#### Evidence E3: Bitwarden's Event Logs Documentation
Documentation for Bitwarden's Event Logs can be found [here](https://bitwarden.com/help/event-logs/). This documentation describes the different types of events that are logged in Bitwarden, including login/logout, secret creation, and vault access. The event logs can be used to track user activity and identify unusual activity.  
  
**Gap:** Events are captured at both the Bitwarden client and server, with most events occurring at the client. While server event capture is instantaneous and quickly processed, clients push event data to the server every 60 seconds, so small delays in the reporting of recent events may be observed. Furthermore, client events data is communicated data an API call, and this is retried until success. As a result, if the client cannot communicate with the API or is somehow modified to not send events then they will not be received and therefore processed. As such, while the contents of the event logs cannot be tampered with, an attacker may be able to prevent their actions from being logged client-side. If an administrator does not have access to Bitwarden's server logs, they may not be able to identify unusual activity in a timely manner.

#### Evidence E4: Bitwarden's Security Whitepaper
Bitwarden's Security Whitepaper can be found [here](https://bitwarden.com/help/bitwarden-security-white-paper/). This whitepaper provides a detailed overview of Bitwarden's security architecture and implementation. The whitepaper includes a detailed description of Bitwarden's encryption protocols, user type access controls, and event logs. Additionally, the whitepaper also includes a section on Bitwarden's security measures, including multi-factor authentication, secure communication protocols, secrets storage, and automated monitoring of Bitwarden cloud infrastructure.  
  
**Gap:** Currently, while Bitwarden has the ability to rotate secrets, there is no documented mechanism for automated secret rotation. 

#### Evidence E5: Bitwarden's Web App and Network Security Assessment
Bitwarden's Web App and Network Security Assessment can be found [here](https://bitwarden.com/help/is-bitwarden-audited/). This assessment provides a detailed overview of Bitwarden's web application and network security architecture and implementation. Bitwarden also regularly conducts comprehensive third-party security audits with notable security firms. These annual audits include source code assessments and penetration testing across Bitwarden IPs, servers, and web applications. The reports for these audits can be found on the same page.  
  
**Gap:** Overall, there are no gaps between the evidence identified for this claim and the documentation provided by Bitwarden.  
  
  
  

### Top Claim 2: Bitwarden audit logs minimize tampering and unauthorized alteration.

#### Evidence E1: Bitwarden Signed Log Configuration and Key Protection Documentation
The documentation can be found [here](https://bitwarden.com/help/event-logs/). Bitwarden signs logs with secure cryptographic keys to ensure log entries cannot be altered without detection. Keys are stored securely and verified before each signing operation.  
  
**Gap:** Key rotation and lifecycle management details are not explicitly described.

#### Evidence E2: Bitwarden Replication Documentation and Immutable Storage Configuration
The documentation can be found [here](https://bitwarden.com/help/data-storage/). Bitwarden stores logs on redundant, cloud-based infrastructure to prevent data loss. Replication ensures log copies are synchronized and recoverable in case of server failure.  
  
**Gap:** No documentation on external integrity verification for replication logs.

#### Evidence E3: Backup Restore Logs
There documentation for backup restore logs can be found [here](https://bitwarden.com/help/export-your-data/). Bitwarden retains and restores backups to maintain log availability. Backup restore logs verify that all log data can be recovered accurately.  
  
**Gap:** Backup frequency and retention duration are not clearly defined in public documentation.

#### Evidence E4: Admin Activity Logs and Access Control Lists
There documentation for admin activity logs and access control lists are found [here](https://bitwarden.com/help/user-types-access-control/). Only administrators with defined roles can access or review audit logs. Access permissions are controlled using role-based access control (RBAC).  
  
**Gap:** Role review automation is not currently documented; permissions may need periodic manual review.

  
#### Overall Assessment
Bitwarden’s audit logging mechanisms provide strong protection against tampering and unauthorized alteration. Minor assurance gaps remain in key lifecycle documentation, replication verification, and access control automation. These can be mitigated by enterprise configurations or policy enforcement.




### Top Claim 3: Bitwarden audit logs minimize tampering and unauthorized alteration.

#### Evidence E1: Client-side vault DB encryption documentation
The documentation [here](https://bitwarden.com/help/what-encryption-is-used/) confirms the use of AES-256-CBC for vault data and PBKDF2-SHA256 for master key derivation. Client applications (desktop, browser, and web) encrypt vault data locally before storage or sync.  
  
**Gap:** The public documentation explains encryption protocols but does not include verifiable client-side implementation logs confirming that the local SQLite vault database is always encrypted before being written to disk.

#### Evidence E2: Static analysis and memory-safety test results
The documentation found [here](https://github.com/bitwarden/clients) on the open-source repository shows that Bitwarden implements PBKDF2-based key derivation with secure memory handling practices. Continuous integration checks include linting and dependency vulnerability scans to detect unsafe memory usage.  
  
**Gap:** There is no published runtime assurance showing that derived keys are properly zeroized in RAM after use, especially for browser-based clients that rely on the WebCrypto API.

#### Evidence E3: Transport-security configuration records and TLS test logs 
Documentation can be found [here](https://bitwarden.com/help/is-bitwarden-audited/). Bitwarden enforces TLS 1.3 connections validated through HTTPS certificate chains. Independent audits verify transport security and encryption mechanisms.  
  
**Gap:** Bitwarden’s public audits confirm TLS usage but do not explicitly document client-side certificate-pinning mechanisms or mitigation strategies for TLS downgrade attempts during synchronization.

#### Evidence E4: Session-timeout configuration documentation and functional results
Documentation for Bitwarden’s vault timeout options are found [here](https://bitwarden.com/help/vault-timeout/?utm_source=chatgpt.com). Bitwarden allows users and administrators to enforce automatic vault locking. On desktop and browser clients, the vault is re-encrypted upon timeout or manual lock.  
  
**Gap:** Timeout policies are user-configurable and may be set too leniently, potentially extending exposure time for decrypted data in client memory or cache.





### Top Claim 4: Bitwarden keeps emergency contact access secure.

#### Evidence E1: Bitwarden Authentication Documentation (2FA, MFA Setup and Enforcement)
Documentation: [Setup Two-Step Login](https://bitwarden.com/help/setup-two-step-login/)  
Bitwarden provides detailed MFA configuration for multiple authentication types: hardware keys (FIDO2), authenticator apps, Duo Security, and email. MFA ensures that even if credentials are compromised, emergency access remains protected by additional verification layers.  
  
**Gap:** MFA setup is optional for free users and not automatically enforced for emergency contacts. Enforcing MFA by default would further strengthen assurance.

#### Evidence E2: Account Monitoring and Recovery Policy Documentation
Documentation: [Recover Your Account](https://bitwarden.com/help/recover-your-account/)  
Describes password recovery, account verification, and ownership validation procedures. These processes ensure only legitimate users regain access after compromise or data loss.  
  
**Gap:** Lacks anomaly-based login detection and notification integration (e.g., geographic login alerts).

#### Evidence E3: Notification System Test Results and Audit Reports
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Bitwarden’s notification and event logging mechanism records every emergency access request and response. Notifications are primarily sent via email or organizational dashboards.  
  
**Gap:** Reliance on email-only notifications poses risk of delay or spoofing. Multi-channel alerts would improve assurance.

#### Evidence E4: Emergency Access Workflow Documentation (Approval, Waiting Period, Policy)
Documentation: [Emergency Access](https://bitwarden.com/help/emergency-access/)  
Explains the process for configuring trusted contacts, waiting period approvals, and vault access transfer.  
  
**Gap:** Waiting periods are user-configurable, which introduces variability. A mandatory minimum threshold is recommended.

#### Evidence E5: Minimum Waiting Period Configuration Documentation and System Logs
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Logs all timestamps and approvals for emergency access requests. Confirms enforcement of the chosen waiting period and auditability of all actions.  
  
**Gap:** Logs are retained for only 367 days, which may be insufficient for compliance in regulated sectors.

#### Evidence E6: Encryption Implementation Details (AES-256-CBC, PBKDF2, RSA-2048)
Documentation: [What Encryption Is Used](https://bitwarden.com/help/what-encryption-is-used/)  
All vault data is end-to-end encrypted using AES-256-CBC with PBKDF2-HMAC-SHA256 for key derivation. RSA-2048 secures shared secrets.  
  
**Gap:** No ECC (Elliptic Curve Cryptography) implementation, which could offer higher efficiency and security margin.

#### Evidence E7: Third-Party Security Audit Reports
Documentation: [Bitwarden Audits](https://bitwarden.com/help/is-bitwarden-audited/)  
Annual independent security assessments validate Bitwarden’s encryption, authentication, and infrastructure integrity.  
  
**Gap:** Only summarized reports are publicly available; more detailed summaries could improve transparency.

#### Evidence E8: Immutable Log Storage Configuration and Access Control Lists
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Logs are append-only and accessible only by system administrators, preventing modification or deletion.  
  
**Gap:** No documented use of tamper-evident hashing or external verification mechanisms for log immutability.

#### Evidence E9: Audit Logs of MFA Events and Phishing Simulation Test Results
Documentation: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)  
Includes MFA event auditing and references internal phishing simulation exercises for continuous validation.  
  
**Gap:** Simulation methodologies are not publicly disclosed; publishing these details could improve external confidence.

#### Overall Assessment
Bitwarden’s documentation aligns strongly with the evidence required to support the top-level claim. Most security mechanisms—MFA, encryption, event logging, and waiting period enforcement—are implemented and well-documented.  
  
Identified gaps primarily concern:
- Optional MFA for free users,  
- Reliance on single-channel notifications, and  
- Limited retention and external verification of logs.  

These are **low-to-moderate assurance gaps** and can be addressed through configuration or enterprise policies.

## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)

## Reflection
As with the previous project deliverables, this assignment was helpful in actually applying what we learned in lecture to our chosen OSS project. This assignment was especially helpful in learning how to construct a proper top claim for a given software. By then developing a case diagram for a given top claim, we were able to identify high-risk security properties for Bitwarden that were in need of assurance.  
  
In our assurance cases, each rebuttal directly addresses real-world client risks, such as plaintext storage, memory exposure, network interception, and prolonged unlocked sessions, and is countered by technical evidence from Bitwarden’s documentation and open-source repositories. Developing this case improved our understanding of assurance reasoning at the client level. Unlike server-side assurances, client protections require additional scrutiny due to variability across environments (web, desktop, mobile). This exercise highlighted the importance of verifying not just cryptographic standards, but also how clients implement and enforce them. Through alignment with group cases (Secrets, Audit Logs, and Emergency Access), this case contributes to a cohesive argument that Bitwarden’s ecosystem systematically minimizes unauthorized access and data exposure across all layers.  
  
Additionally, this project helped us gain more confidence in analyzing system security and showed us that having evidence and documentation is important to prove that the system really works the way it should, which contributes to system trustworthiness.  
  
Finally, as a team, we were able to improve our collaboration efforts. As per the professor's feedback, we were able to better communicate our ideas and progress to each other so that the final deliverable was consistent and of high quality.
