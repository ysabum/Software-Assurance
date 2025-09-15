# [Team 6](https://github.com/users/ysabum/projects/1)
## Open-Source Software Project
[Bitwarden](https://github.com/bitwarden/clients)
## Hypothetical Operational Environment
Our hypothetical operation environment is for a national retail bank, where the company is developing a secure online banking application that allows customers to manage their accounts, transfer funds, pay bills, and apply for loans. The company expects to integrate a security tool like Bitwarden to protect credentials and sensitive financial operations for both the employees and customers.
## Systems Engineering View
![image](https://raw.githubusercontent.com/ysabum/Software-Assurance/af70d3762b696d61c5889dad0580611a4998648c/images/SED.png)
## Perceived Threats
- Credential theft 
- Unauthorized access
- Phishing/Fake websites from spoofing
- Compromised devices due to malware
- Data breaches/Bitwarden cloud server breach
-Multi-Factor Authentication (MFA) attacks
## List of Security Features
- End-to-End encryption: All vault data is encrypted locally on the device before syncing. Bitwarden cannot see or access user passwords
- AES-256 bit encryption with PBKDF2 SHA-256 and Argon2 key derivation: Strong cryptography protects vault contents from brute-force attacks
- Master Password Protection: Single strong credential required to unlock the vault; never transmitted to servers
  - Includes biometric unlock
- Multi-Factor Authentication (MFA)
- Password generator: Creates strong, random, unique passwords to reduce reuse and guessing attacks
- Secure autofill and domain matching: Autofill only works on verified domains, mitigating phishing risks
- Vault timeout and auto-lock
- Vault Health Reports
- Encrypted cloud storage
- Role-based access control for enterprises: Administrators can restrict which employees access specific credentials
  - Also securely share credentials with specific groups, not the entire organization
- Audit logs for enterprises
- Self-hosting option: Enterprises and banks can deploy Bitwarden on their own infrastructure for full control
## Team Motivation
When our team had our first meeting, we came up with several open source softwares that we wanted to work on and eventually narrowed down our choice to Bitwarden, as it is a password manager that deals with a lot of sensitive user data for users at home and for enterprises, and is thus in need of software assurance. Additionally, Bitwarden is a larger-sized active project with a number of collaborators and is written in a well-known language (C#, TypeScript/JavaScript), making it an inviting OSS considering our team members prior knowledge. 
