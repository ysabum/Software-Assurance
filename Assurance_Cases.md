# Assurance Case for Software Security Engineering
## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)

## Top Claim 1 
[Bitwarden's Secrets Manager minimizes unauthorized access to secrets.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Secrets/Secrets.md)

![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Secrets/Secrets.drawio.png?raw=true)

#### Evidence 1: Bitwarden's Encryption Protocols
Documentation for Bitwarden's Encryption Protocols can be found [here](https://bitwarden.com/help/what-encryption-is-used/). This documentation describes the encryption protocols used by Bitwarden to encrypt secrets; the protocols include AES-256-CBC and PBKDF2-HMAC-SHA256. These protocols are chosen to provide strong encryption and to be compatible with the latest standards. All vault data (including secrets) is strongly encrypted by Bitwarden before being stored anywhere. Bitwarden provides a backup option to encrypt the secrets before uploading them to the cloud.  
  
Overall, there are no gaps between the evidence identified for this claim and the documentation provided by Bitwarden.

#### Evidence 2: Bitwarden's User Type Access Controls
Documentation for Bitwarden's User Type Access Controls can be found [here](https://bitwarden.com/help/managing-users/) and [here](https://bitwarden.com/help/user-types-access-control/). This documentation describes the different user types and their access controls in Bitwarden. Bitwarden provides four main user types: user, admin, owner, and custom. Whether a member can access the Secrets Manager depends on their user type and their access controls.  
  
Overall, there are no gaps between the evidence identified for this claim and the documentation provided by Bitwarden.

#### Evidence 3: Bitwarden's Event Logs Documentation
Documentation for Bitwarden's Event Logs can be found [here](https://bitwarden.com/help/event-logs/). This documentation describes the different types of events that are logged in Bitwarden, including login/logout, secret creation, and vault access. The event logs can be used to track user activity and identify unusual activity.  
  
**Gap:** Events are captured at both the Bitwarden client and server, with most events occurring at the client. While server event capture is instantaneous and quickly processed, clients push event data to the server every 60 seconds, so small delays in the reporting of recent events may be observed. Furthermore, client events data is communicated data an API call, and this is retried until success. As a result, if the client cannot communicate with the API or is somehow modified to not send events then they will not be received and therefore processed. As such, while the contents of the event logs cannot be tampered with, an attacker may be able to prevent their actions from being logged client-side. If an administrator does not have access to Bitwarden's server logs, they may not be able to identify unusual activity.


#### Evidence 4: Bitwarden's Security Whitepaper
Bitwarden's Security Whitepaper can be found [here](https://bitwarden.com/help/bitwarden-security-white-paper/). This whitepaper provides a detailed overview of Bitwarden's security architecture and implementation. The whitepaper includes a detailed description of Bitwarden's encryption protocols, user type access controls, and event logs. Additionally, the whitepaper also includes a section on Bitwarden's security measures, including multi-factor authentication, secure communication protocols, secrets storage, and automated monitoring of Bitwarden cloud infrastructure.  
  
**Gap:** Currently, while Bitwarden has the ability to rotate secrets, there is no documented mechanism for automated secret rotation. 

#### Evidence 5: Bitwarden's Web App and Network Security Assessment
Bitwarden's Web App and Network Security Assessment can be found [here](https://bitwarden.com/help/is-bitwarden-audited/). This assessment provides a detailed overview of Bitwarden's web application and network security architecture and implementation. Bitwarden also regularly conducts comprehensive third-party security audits with notable security firms. These annual audits include source code assessments and penetration testing across Bitwarden IPs, servers, and web applications. The reports for these audits can be found on the same page.  
  
Overall, there are no gaps between the evidence identified for this claim and the documentation provided by Bitwarden.

## Reflection

## Top Claim 2: Bitwarden Audit Log Assurance Case

## Top Claim (C1):
[Bitwarden audit logs minimize tampering and unauthorized alteration.] (https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Audit_logs/README.md)

---

## Context
Bitwarden is an open-source password manager that records critical user and system actions.  
The audit log subsystem helps ensure accountability by detecting unauthorized or unexpected modifications to user data and system configuration.

---

## Justification
This assurance case argues that Bitwarden maintains trustworthy audit logs by ensuring integrity, availability, and restricted access.  
Security mechanisms such as cryptographic signing, replication, **backup enforcement, and **role-based access control** collectively ensure that audit logs cannot be modified or deleted without detection.

---

## Evidence

### **E1: Bitwarden Signed Log Configuration and Key Protection Documentation**
**Link:** [https://bitwarden.com/help/event-logs/](https://bitwarden.com/help/event-logs/)  
**Description:**  
Bitwarden signs logs with secure cryptographic keys to ensure log entries cannot be altered without detection.  
Keys are stored securely and verified before each signing operation.  
**Gap:** Key rotation and lifecycle management details are not explicitly described.

---

### **E2: Bitwarden Replication Documentation and Immutable Storage Configuration**
**Link:** [https://bitwarden.com/help/data-storage/](https://bitwarden.com/help/data-storage/)  
**Description:**  
Bitwarden stores logs on redundant, cloud-based infrastructure to prevent data loss.  
Replication ensures log copies are synchronized and recoverable in case of server failure.  
**Gap:** No documentation on external integrity verification for replication logs.

---

### E3: Backup Restore Logs
**Link:** [https://bitwarden.com/help/export-your-data/](https://bitwarden.com/help/export-your-data/)  
**Description:**  
Bitwarden retains and restores backups to maintain log availability.  
Backup restore logs verify that all log data can be recovered accurately.  
**Gap:** Backup frequency and retention duration are not clearly defined in public documentation.

---

### E4: Admin Activity Logs and Access Control Lists
**Link:** [https://bitwarden.com/help/user-types-access-control/](https://bitwarden.com/help/user-types-access-control/)  
**Description:**  
Only administrators with defined roles can access or review audit logs.  
Access permissions are controlled using role-based access control (RBAC).  
**Gap:** Role review automation is not currently documented; permissions may need periodic manual review.

---

## Alignment and Gaps Summary

| **Integrity** | Logs are digitally signed and verified using secure keys. | Key rotation policy not detailed. |
| **Availability** | Logs are replicated across servers with backups. | No external replication verification. |
| **Access Control** | Restricted admin-only access to audit logs. | Manual role reviews; lack of automation. |
| **Backup & Retention** | Backup logs ensure long-term data recovery. | Retention period not publicly stated. |

**Overall Assessment:**  
Bitwarden’s audit logging mechanisms provide strong protection against tampering and unauthorized alteration.  
Minor assurance gaps remain in key lifecycle documentation, replication verification, and access control automation.  
These can be mitigated by enterprise configurations or policy enforcement.

---

## Reflection
This assurance case demonstrates how Bitwarden ensures audit log trustworthiness through multiple defensive layers.  
The process of mapping subclaims and rebuttals clarified how cryptographic integrity, replication, backup enforcement, and access control together support the top claim.  
It also highlighted improvement areas, such as automating role reviews and external verification of replication integrity.

By connecting real documentation links as evidence, this assurance case moves beyond theory — showing clear proof of Bitwarden’s reliability and transparency.

---

## References
- Bitwarden Help Center: [https://bitwarden.com/help/](https://bitwarden.com/help/)  
- Bitwarden Event Logs: [https://bitwarden.com/help/event-logs/](https://bitwarden.com/help/event-logs/)  
- Bitwarden Data Storage: [https://bitwarden.com/help/data-storage/](https://bitwarden.com/help/data-storage/)  
- Bitwarden Access Control: [https://bitwarden.com/help/user-types-access-control/](https://bitwarden.com/help/user-types-access-control/)

---


## Deekshith Reflection
Working on this assurance case helped me understand how Bitwarden keeps its audit logs safe from tampering or deletion.  
By breaking the system into smaller parts like signing, replication, backups, and admin access, I learned how each layer protects the logs in a different way.  
It also showed me that having evidence and documentation is important to prove that the system really works the way it should.  
Overall, this project helped me connect what I learned in class to a real open-source tool and made me more confident in analyzing system security.

---


## Top Claim-3

[Bitwarden Keeps Emergency Contact Access Secure.](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Emergency_access/emergency_access.md)

![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Emergency_access/assuranceCaseEA.drawio.png?raw=true)

**Top Claim:** Bitwarden Keeps Emergency Contact Access Secure.  

**Context:**  
In the online banking environment, Bitwarden enables bank customers to designate trusted emergency contacts who can request vault access in case the account owner becomes unavailable (e.g., medical emergencies or forgotten master password).  

**Justification:**  
This claim argues that the Emergency Access feature in Bitwarden ensures only authorized and verified contacts can access vault data under controlled and auditable conditions. Security mechanisms such as encryption, MFA, waiting period enforcement, and event logging collectively support this assurance.

## Evidence

### **E1: Bitwarden Authentication Documentation (2FA, MFA Setup and Enforcement)**
Documentation: [Setup Two-Step Login](https://bitwarden.com/help/setup-two-step-login/)  
Bitwarden provides detailed MFA configuration for multiple authentication types: hardware keys (FIDO2), authenticator apps, Duo Security, and email. MFA ensures that even if credentials are compromised, emergency access remains protected by additional verification layers.  

**Gap:** MFA setup is optional for free users and not automatically enforced for emergency contacts. Enforcing MFA by default would further strengthen assurance.

### **E2: Account Monitoring and Recovery Policy Documentation**
Documentation: [Recover Your Account](https://bitwarden.com/help/recover-your-account/)  
Describes password recovery, account verification, and ownership validation procedures. These processes ensure only legitimate users regain access after compromise or data loss.  

**Gap:** Lacks anomaly-based login detection and notification integration (e.g., geographic login alerts).

### **E3: Notification System Test Results and Audit Reports**
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Bitwarden’s notification and event logging mechanism records every emergency access request and response. Notifications are primarily sent via email or organizational dashboards.  

**Gap:** Reliance on email-only notifications poses risk of delay or spoofing. Multi-channel alerts would improve assurance.

### **E4: Emergency Access Workflow Documentation (Approval, Waiting Period, Policy)**
Documentation: [Emergency Access](https://bitwarden.com/help/emergency-access/)  
Explains the process for configuring trusted contacts, waiting period approvals, and vault access transfer.  

**Gap:** Waiting periods are user-configurable, which introduces variability. A mandatory minimum threshold is recommended.

### **E5: Minimum Waiting Period Configuration Documentation and System Logs**
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Logs all timestamps and approvals for emergency access requests. Confirms enforcement of the chosen waiting period and auditability of all actions.  

**Gap:** Logs are retained for only 367 days, which may be insufficient for compliance in regulated sectors.

### **E6: Encryption Implementation Details (AES-256-CBC, PBKDF2, RSA-2048)**
Documentation: [What Encryption Is Used](https://bitwarden.com/help/what-encryption-is-used/)  
All vault data is end-to-end encrypted using AES-256-CBC with PBKDF2-HMAC-SHA256 for key derivation. RSA-2048 secures shared secrets.  

**Gap:** No ECC (Elliptic Curve Cryptography) implementation, which could offer higher efficiency and security margin.


### **E7: Third-Party Security Audit Reports**
Documentation: [Bitwarden Audits](https://bitwarden.com/help/is-bitwarden-audited/)  
Annual independent security assessments validate Bitwarden’s encryption, authentication, and infrastructure integrity.  

**Gap:** Only summarized reports are publicly available; more detailed summaries could improve transparency.


### **E8: Immutable Log Storage Configuration and Access Control Lists**
Documentation: [Event Logs](https://bitwarden.com/help/event-logs/)  
Logs are append-only and accessible only by system administrators, preventing modification or deletion.  

**Gap:** No documented use of tamper-evident hashing or external verification mechanisms for log immutability.


### **E9: Audit Logs of MFA Events and Phishing Simulation Test Results**
Documentation: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)  
Includes MFA event auditing and references internal phishing simulation exercises for continuous validation.  

**Gap:** Simulation methodologies are not publicly disclosed; publishing these details could improve external confidence.


## Alignment and Gaps Summary

Overall, Bitwarden’s documentation aligns strongly with the evidence required to support the top-level claim.  
Most security mechanisms—MFA, encryption, event logging, and waiting period enforcement—are implemented and well-documented.  
Identified gaps primarily concern:
- Optional MFA for free users,  
- Reliance on single-channel notifications, and  
- Limited retention and external verification of logs.  

These are **low-to-moderate assurance gaps** and can be addressed through configuration or enterprise policies.


## AI Prompt and Reflection

**AI Prompt Used:**  
> “You are an expert software assurance engineer. Your job is to refine the phrasing of assurance claims for the Bitwarden Emergency Access feature. Each claim must include an entity, a security property, and a measurable value, and avoid phrasing about implementation methods.”

**Usefulness Reflection:**  
This prompt helped reframe the team’s thinking from “Bitwarden uses AES encryption” to “Bitwarden ensures vault data remains confidential.”  
It improved the logical precision of our claims and focused the assurance argument on security *outcomes* rather than technical *means*. This approach made the assurance case more persuasive and aligned with stakeholder expectations.


## Swetha's Reflection

Building this assurance case clarified how strong documentation and open-source transparency contribute to system trustworthiness.  
Mapping misuse cases to concrete security requirements made it easier to evaluate where Bitwarden already provides protection and where improvements are needed.  
The most valuable learning was distinguishing between a security *feature* and a *claim of assurance*.  
While encryption or MFA are technical features, assurance comes from demonstrating—with evidence—that they function correctly, consistently, and under all relevant conditions.


