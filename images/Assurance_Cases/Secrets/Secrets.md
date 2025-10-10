## Top Claim: Bitwarden's Secrets Manager minimizes unauthorized access to secrets
![image](https://github.com/ysabum/Software-Assurance/blob/main/images/Assurance_Cases/Secrets/Secrets.drawio.png?raw=true)

## Alignment of the Evidence and Gaps
### Top Claim: Bitwarden's Secrets Manager minimizes unauthorized access to secrets
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
As with the previous project deliverables, this assignment was helpful in actually applying what we learned in lecture to our chosen OSS project. This assignment was especially helpful in learning how to construct a proper top claim for a given software. By then developing a case diagram for a given top claim, we were able to identify high-risk security properties for Bitwarden that were in need of assurance. 
  
As for our team, we were able to improve our collaboration efforts. As per the professor's feedback, we were able to better communicate our ideas and progress to each other so that the final deliverable was of high and consistent quality. 