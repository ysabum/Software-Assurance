# Designing for Software Security Engineering

## Data Flow Diagrams and Threat Modeling Reports
- [Diagram: Secrets Managers](https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/secrets_manager/secrets.png)
- [Diagram: Emergency Access](https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/emergencyContactAccess/trustedcontact.png)
- [Threat Modeling Report for Secrets Manager](https://htmlpreview.github.io/?https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/secrets_manager/secrets_report.htm)
- [Threat Modeling Report for Emergency Access](https://htmlpreview.github.io/?https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/emergencyContactAccess/trusted_contact_dfd1_report.htm)

## Review of Mitigations in the Bitwarden
Bitwarden implements nearly all expected mitigations derived from Level 1 DFD-based STRIDE threat analysis. Together, these directly map to the STRIDE threats identified in  Level-1 DFD TMT report (spoofing, tampering, repudiation, disclosure, DoS, and EoP).


### Mitigations Implemented According to the DFD Threat Modeling Reports

The threat models applies a comprehensive set of mitigations focused on preventing spoofing through strong mutual authentication, protecting all communications with mandatory TLS 1.2+ and encrypted service mesh traffic, enforcing strict schema-based input validation to prevent tampering and code execution, implementing comprehensive audit logging for non-repudiation and traceability, and applying availability controls including rate limiting, autoscaling, resource constraints, and database failover. These mitigations protect the integrity and confidentiality of secrets as they move through the Bitwarden Secrets Manager and Emergency Access architecture.

### Identified Gaps and Documentation
We reviewed official documentation (including the Security Whitepaper, Secrets Manager Help pages, Organization management docs, Event Log documentation, and Emergency Access documentation) to determine which expected mitigations are documented and which are missing. Below is a summary of documented mitigations and gaps where Bitwarden provides insufficient documentation and/or has not implemented certain mitigations:

1. **Bitwarden's Encryption Protocols:** Documentation can found [here](https://bitwarden.com/help/what-encryption-is-used) and [here](https://bitwarden.com/help/bitwarden-security-white-paper/#hashing-key-derivation-and-encryption) details how cryptographic keys are derived for PBKDF2-SHA256 or Argon2id, the “Protected Symmetric Key” generation and that it’s never stored in plaintext on the server, the use of AES-CBC 256-bit encryption for vault data, and HMAC (or similar) to validate integrity, and an explanation of key stretching, master key, and zero-knowledge architecture.  
  
    **Gap:** No documentation of token anti-replay protections, token TTL/expiration policies for machine tokens, token revocation procedures, HSM or hardware-backed key protection, or internal encryption service isolation.

2. **Authentication Mechanisms:** Documentation seen [here](https://bitwarden.com/help/login-with-sso) and [here](https://bitwarden.com/help/secrets-manager-overview) shows that Bitwardensupports strong user authentication through OIDC/SSO integration, MFA (TOTP, Duo, WebAuthn), and passwordless login. Bitwarden also supports machine accounts and access tokens for programmatic access.
  
    **Gap:** Documentation does not specify internal validation details for machine access tokens (e.g., signature algorithm, audience/scopes, TTL, nonce use). Bitwarden also does not publicly document anti-replay protections, short-lived token requirements, or mutual TLS/service-to-service authentication for backend components.

3. **Bitwarden's User Type Access Controls:** Documentation for Bitwarden's User Type Access Controls can be found [here](https://bitwarden.com/help/managing-users) and [here](https://bitwarden.com/help/user-types-access-control). This documentation describes the different user types and their access controls in Bitwarden. Bitwarden provides four main user types: user, admin, owner, and custom. Whether a member can access the Secrets Manager depends on their user type and their access controls. 
  
    **Gap:** Documentation does not describe the enforcement model for machine accounts and service tokens. There are no details are provided on how Bitwarden performs service-to-service authorization beyond the existence of machine tokens.

4. **Bitwarden's Organization/Role/Access Control:** Documentation can be found [here](https://bitwarden.com/help/manage-your-secrets-org). The documentation shows additional details on member roles (User, Admin, Owner) and their secrets-manager-specific permissions. Additionally, the documentation shows support for SCIM (automated provisioning), which links to identity provider integration, and information on account recovery administration.
  
    **Gap:** Documentation does not explain security hardening around SCIM provisioning or account recovery protections. Additionally, backend controls such as DB authentication, RCE protection, anti-replay, and DoS mitigation are not described in public documentation.

5. **Bitwarden's Secrets Manager Startup:** Documentation can be found [here](https://bitwarden.com/help/secrets-manager-quick-start). The documentation shows how to activate the Secrets Manager for organization members, that access tokens are tied to machine accounts, and that there are role-based permissions on projects (“Can read”, “Can read, write,” etc.) for both people and machines.  
  
   **Gap:** Documentation does not state token signing algorithm, lifetime/rotation, revocation procedure, or anti-replay specifics. Again, there is no mention of mTLS/service-to-service mutual auth, DB authentication, anti-replay, DoS mitigation, token revocation.

6. **Bitwarden’s Secrets Manager Startup:** Documentation can be found [here](https://bitwarden.com/help/secrets-manager-quick-start). It shows that access tokens are tied to machine accounts and that project-level permissions control read/write access for both users and machines.

    **Gap:** Documentation does not state token signing details, token rotation schedule, token lifetime enforcement, revocation methods, or anti-replay protections. There is also no public documentation of mTLS/service identity authentication between backend services or database authentication for the Secrets Manager.

7. **Bitwarden's Event Logs:** Documentation can be found [here](https://bitwarden.com/help/event-logs). The documentation shows the types of events logged, including Secrets Manager events (e.g., “Accessed a secret”, “Created a secret”, etc.) and that event logs are exportable via API (/events endpoint) and retained (with some retention settings). [Bitwarden Event Logs in Whitepaper](https://bitwarden.com/pdf/help-event-logs.pdf) confirms certain event IDs for secrets access (e.g., 2100 = “Accessed secret”).      
    
    **Gap:** Documentation does not specify whether logs are tamper-resistant, signed, write-once, or protected from insider modification. Retention guarantees, log integrity protection, or real-time alert thresholds are also not described.

8. **Strong Identity Verification (MFA and Trusted Contact Enrollment):** [Bitwarden supports multiple forms of MFA](https://bitwarden.com/help/setup-two-step-login)including FIDO2, Duo, authenticator apps, email-based codes, and YubiKey OTP. This mitigates spoofing risks for Trusted Emergency Contacts.

9. **Enforced Waiting Period & Approval Workflow:** The Emergency Access workflow includes a [configurable waiting period and explicit approval or denial steps.](https://bitwarden.com/help/emergency-access/#trusted-emergency-contacts). Bitwarden notifies the vault owner for each [emergency access request](https://bitwarden.com/help/emergency-access).

    **Gap:** Emergency contacts do not need a paid subscription, which means they are not required to enable MFA. This creates a policy-level gap where the emergency contact may authenticate with weaker security than the vault owner, increasing the chance of spoofing. The vault owner sets the waiting period length freely. Users may choose an insecurely short waiting period, weakening the protection intended by this control. These two gaps are policy issues rather than architectural flaws.

10. **End-to-End Encryption on All Vault and Emergency Access Data:** Bitwarden uses [AES-256-CBC, RSA-2048, and PBKDF2-HMAC-SHA256 for encryption and key derivation.](https://bitwarden.com/help/bitwarden-security-white-paper/#hashing-key-derivation-and-encryption) These controls mitigate tampering, disclosure, and EoP (Elevation of Privilege) risks.

11. **Zero-Knowledge Cryptographic Design:** Prevents Bitwarden (or an attacker) from [decrypting user vaults](https://bitwarden.com/resources/zero-knowledge-encryption).

12. **Annual Third-Party Security Audits:** [Mitigates risks arising from implementation flaws](https://bitwarden.com/help/is-bitwarden-audited/#third-party-security-audits).


## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)


## Team Reflection

Working on the Emergency Access and Secrets Manager features in Bitwarden helped us understand how important it is to look closely at how data moves through a system. Creating the DFD and doing the STRIDE analysis showed us where weaknesses can appear and why trust boundaries matter.

Additionally, reviewing Bitwarden’s documentation helped in connecting the threats in the model to the actual controls in the system, such as encryption, logging, and the waiting period. Noticing gaps like optional MFA for emergency contacts also helped in seeing how certain user settings can reduce security.

Overall, this assignment helped us develop a clearer view of how to analyze a feature, understand its risks, and match threats to real-world mitigations.
