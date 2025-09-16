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
- Multi-Factor Authentication (MFA) attacks
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
## Open-Source Project Description
### **What Is It?**
- The Bitwarden Clients is the monorepo containing Bitwarden's official client applications. This includes the web vault, browser extensions, desktop apps, and the CLI for interacting with Bitwarden password management services. These applications allow users to securely manage and access passwords and other sensitive information across multiple devices, ensuring seamless synchronization and protection.
  
GitHub Repository: https://github.com/bitwarden/clients  
  
### **Contributors & Activity**
- The project maintains an active open-source community, with regular contributions from developers around the world. This activity is reflected in:
  - Open Issues: 1,183, showing ongoing development and user engagement
  - Forks: 1,488, demonstrating active community contributions
  - Stars/Watchers: 11,241, highlighting broad adoption and interest
- Developers frequently submit updates, bug fixes, and feature improvements, ensuring the clients remain secure and reliable.
  
### **Popularity & Use**
-	Bitwarden is a widely used open-source password manager, valued for its transparency, security, and support across multiple platforms.
-	The client applications allow users to securely store and manage passwords, notes, and other sensitive data via web browsers, desktops, and the CLI.
  
### **Languages & Technologies**  
The repository leverages a mix of modern programming technologies:  
- TypeScript & JavaScript – core logic and client functionality
- Electron – desktop app development
- Angular – web app framework
- Node.js – supporting CLI and backend utilities
- HTML/CSS – interface structure and styling
  
### **Platforms**  
Bitwarden client applications are available on:  
-	Web Browsers – Chrome, Firefox, Safari, Edge
-	Desktop – Windows, macOS, Linux
-	Command-Line Interface – cross-platform CLI for advanced users
-	Browser Extensions – secure password access directly in browsers
  
### **Documentation & Resources**  
The project offers comprehensive documentation and community support:  
-	README files, wiki pages, and GitHub discussions provide guidance on setup, usage, and contribution.
-	Security policies and reporting procedures ensure responsible use and contribution.
  
### **Licensing & Contributor Licensing**  
Licensing information (GPL-3.0 and Bitwarden License v1.0)  
-	The repository is licensed under GPL-3.0, ensuring that all derivative work remains open-source under the same license.
-	Contributors must agree to the Bitwarden Contributor License Agreement (CLA), which clarifies that contributions can be included in the project under the GPL-3.0 license while protecting the project’s legal integrity.
-	Security, copyright, and contribution policies are documented to guide safe and legally compliant par.

## Security History of Bitwarden

Bitwarden has always focused on protecting the user data with end to end encryption. All the information is encrypted on the users own device before it sent to the cloud, so Bitwarden server never see the real passwords or the confidential information. The system relies on the Security algorithms like AES-256 encryption and PBKDF2-SHA256 key stretching to make the passwords hard to crack. In back 2018, the security firm cure53 audited the web vault, browser extensions and the server code, finding only small issues that were fixed right away. Followup cure53 audits in 2020 and 2022 reviewed new futures again and conformed the strength of the design while suggesting a few extra hardening steps that were implemented. Bitwarden also runs the public bug bounty program on the Hacker One which invites the researchers to report the problems. Through this program minor issues like URL parsing bugs, timing attack risks, Content security policy improvements were discovered and quickly patched. Over the time the company has steadily increased the PBKDF2 iteration count to resist the Brute force attacks. Security features have been expanded to include the two factor authentication and later FIDO@/ WebAuthn hardware key support for strong account logins. In the year 2021, Bitwarden introduced the Secrets manager to help developers protect the credentials. Browser extension logic was hardened to block auto fill on fake or unauthorized websites. No major breaches have been reported, and every known issue has been addressed promptly.  
  
Overall, Bitwarden's History shows the regular independent audits, responsible disclosure, quick fixes, and continuous engineering improvements to keep the user data safe.

## **License, Contribution Procedures, and Contributor Agreements**

### **License**
The Bitwarden clients repository is distributed under the **GNU General Public License version 3 (GPL-3.0)**. This license guarantees end users the freedom to run, study, share, and modify the software. However, it also enforces the principle of “copyleft,” which requires that any redistributed versions or derivative works remain licensed under GPL-3.0. In practice, this ensures that improvements made by the community remain open and available to all users.

### **Contribution Procedures**
Bitwarden maintains a structured workflow for external contributions, documented in its Contributing Guide:

1. **Repository Forking and Branching:**  Contributors fork the repository and develop changes in a feature branch. 
2. **Coding Standards:** Submissions must comply with project style guidelines, include descriptive commit messages, and, when applicable, provide automated test coverage and documentation updates. 
3. **Pull Request Submission:** Once ready, contributions are submitted as a Pull Request (PR). Maintainers then evaluate technical soundness, adherence to guidelines, and alignment with the project’s objectives.
4. **Review and Merge:** After feedback and necessary revisions, approved PRs are merged into the main codebase.

### **Contributor Agreements**
To safeguard intellectual property rights and project integrity, Bitwarden requires contributors to acknowledge its Contributor License Agreement (CLA). The CLA confirms that contributors either own the code they submit or have the legal right to license it, thereby allowing Bitwarden to incorporate the contribution without legal ambiguity. This process provides clarity for both contributors and maintainers, ensuring that the project can confidently integrate external work.

## Project Reflections
Initially, we had difficulty finding a time that we could all meet to discuss our team roles and software choices as we had a lot of conflicting schedules with other classes and/or work. Additionally, our team had some confusion in choosing an OSS that was in need of software assurance. However, as a testament to our teamwork, we were successfully able to find a time slot that worked for all our members, as well as, with some discussion with our professor, find an OSS that matched all of our team member's interests.  
  
As a team, we learned that it is important to have an open line of communication. If any one member has ideas for changes to the project, if they are have any difficulties, etc., it is important to always keep the team as a whole up-to-date. We also found having a set schedule for when deliverables are due (some time prior to the actual assignment due date) and a set assignment for each team member to useful for keeping the team on track. 
