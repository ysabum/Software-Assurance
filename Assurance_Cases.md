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

## Top Claim-2

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


