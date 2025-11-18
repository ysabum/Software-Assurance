# Designing for Software Security Engineering

## Data Flow Diagrams and Threat Modeling Reports
- [Diagram: Login and Secrets Managers](https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/secrets_manager/secrets.png)
- [Diagram: Emergency Access](https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/emergencyContactAccess/eca.png)
- [Threat Modeling Report for Login and Secrets Manager](https://htmlpreview.github.io/?https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/secrets_manager/secrets_report.htm)
- [Threat Modeling Report for Emergency Access](https://htmlpreview.github.io/?https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/emergencyContactAccess/trusted_contact_dfd1_report.htm)

## Review of Mitigations in the Bitwarden
Bitwarden implements nearly all expected mitigations derived from Level 1 DFD-based STRIDE threat analysis. Together, these directly map to the STRIDE threats identified in  Level-1 DFD TMT report (spoofing, tampering, repudiation, disclosure, DoS, and EoP).


### Mitigations Implemented According to the DFD Threat Modeling Reports

The threat models applies a comprehensive set of mitigations focused on preventing spoofing through strong mutual authentication, protecting all communications with mandatory TLS 1.3 and encrypted service mesh traffic, enforcing strict schema-based input validation to prevent tampering and code execution, implementing robust audit logging for non-repudiation and traceability, and applying availability controls including rate limiting, autoscaling, resource constraints, and database failover. These mitigations protect the integrity and confidentiality of secrets as they move through the Bitwarden Secrets Manager and Emergency Access architecture.

### Identified Gaps and Documentation
We reviewed official documentation (including the Security Whitepaper, Secrets Manager Help pages, Organization management docs, Event Log documentation, and Emergency Access documentation) to determine which expected mitigations are documented and which are missing. Below is a summary of documented mitigations and gaps where Bitwarden provides insufficient documentation and/or has not implemented certain mitigations:

1. **Bitwarden's Encryption Protocols:** Documentation can found [here](https://bitwarden.com/help/what-encryption-is-used) and [here](https://bitwarden.com/help/bitwarden-security-white-paper/#hashing-key-derivation-and-encryption) details how cryptographic keys are derived for PBKDF2-SHA256 or Argon2id, the “Protected Symmetric Key” generation and that it’s never stored in plaintext on the server, the use of AES-CBC 256-bit encryption for vault data, and HMAC (or similar) to validate integrity, and an explanation of key stretching, master key, and zero-knowledge architecture.  
  
    **Gap:** No documentation of token anti-replay protections, token TTL, session expiration, revocation, internal encryption service design, HSM use, secure enclave, or hardware-backed key protection, or key rotation policies for the Secrets Manager.

2. **Authentication Mechanisms:** Documentation seen [here](https://bitwarden.com/help/login-with-sso) and [here](https://bitwarden.com/help/secrets-manager-overview) shows that Bitwardensupports strong user authentication through OIDC/SSO integration, MFA (TOTP, Duo, WebAuthn), and passwordless login. Bitwarden also supports machine accounts and access tokens for programmatic access.
  
    **Gap:** Documentation does now specify how access tokens are validated internally (signature type, lifetime, nonce use, etc.). Additionally, there is no documented protections against replay attacks, stolen token reuse, or token binding between services, as well as no documentation on mutual TLS between backend components.

3. **Bitwarden's User Type Access Controls:** Documentation for Bitwarden's User Type Access Controls can be found [here](https://bitwarden.com/help/managing-users) and [here](https://bitwarden.com/help/user-types-access-control). This documentation describes the different user types and their access controls in Bitwarden. Bitwarden provides four main user types: user, admin, owner, and custom. Whether a member can access the Secrets Manager depends on their user type and their access controls. 
  
    **Gap:** Documentation does not specify enforcement model for machine accounts or service tokens (scope, aud, TTL). Additionally, there is no token format/signing/verification details and service-to-service auth.

4. **Bitwarden's Organization/Role/Access Control:** Documentation can be found [here](https://bitwarden.com/help/manage-your-secrets-org). The documentation shows additional details on member roles (User, Admin, Owner) and their secrets-manager-specific permissions. Additionally, the documentation shows support for SCIM (automated provisioning), which links to identity provider integration, and information on account recovery administration.
  
    **Gap:** Account recovery and SCIM introduce attack surface, so there is a need to ensure recovery is sufficiently protected and that the threat model documents those protections. There is no mention of service auth, anti-replay, DB auth, RCE, DoS, etc.

5. **Bitwarden's Secrets Manager Startup:** Documentation can be found [here](https://bitwarden.com/help/secrets-manager-quick-start). The documentation shows how to activate the Secrets Manager for organization members, that access tokens are tied to machine accounts, and that there are role-based permissions on projects (“Can read”, “Can read, write,” etc.) for both people and machines.  
  
   **Gap:** Documentation does not state token signing algorithm, lifetime/rotation, revocation procedure, or anti-replay specifics. Again, there is no mention of mTLS/service-to-service mutual auth, DB authentication, anti-replay, DoS mitigation, token revocation.

5. **Bitwarden's Event Logs:** Documentation can be found [here](https://bitwarden.com/help/event-logs). The documentation shows the types of events logged, including Secrets Manager events (e.g., “Accessed a secret”, “Created a secret”, etc.) and that event logs are exportable via API (/events endpoint) and retained (with some retention settings). [Bitwarden Event Logs in Whitepaper](https://bitwarden.com/pdf/help-event-logs.pdf) confirms certain event IDs for secrets access (e.g., 2100 = “Accessed secret”).      
    
    **Gap:** Available documentation does not guarantee tamper-resistance or integrity of logs (who can delete/modify logs, retention guarantees, immutability or write-once storage). Real-time alerting thresholds, SIEM integration specifics, and how logs are protected from insider tampering.

6. **Strong Identity Verification (MFA and Trusted Contact Enrollment):** [Bitwarden supports multiple forms of MFA](https://bitwarden.com/help/setup-two-step-login)including FIDO2, Duo, authenticator apps, email-based codes, and YubiKey OTP. This mitigates spoofing risks for Trusted Emergency Contacts.

7. **Enforced Waiting Period & Approval Workflow:** The Emergency Access workflow includes a [configurable waiting period and explicit approval or denial steps.](https://bitwarden.com/help/emergency-access/#trusted-emergency-contacts). Bitwarden notifies the vault owner for each [emergency access request](https://bitwarden.com/help/emergency-access).

    **Gap:** Emergency contacts do not need a paid subscription, which means they are not required to enable MFA. This creates a policy-level gap where the emergency contact may authenticate with weaker security than the vault owner, increasing the chance of spoofing. The vault owner sets the waiting period length freely. Users may choose an insecurely short waiting period, weakening the protection intended by this control. These two gaps are policy issues rather than architectural flaws.

8. **End-to-End Encryption on All Vault and Emergency Access Data:** Bitwarden uses [AES-256-CBC, RSA-2048, and PBKDF2-HMAC-SHA256 for encryption and key derivation.](https://bitwarden.com/help/bitwarden-security-white-paper/#hashing-key-derivation-and-encryption) These controls mitigate tampering, disclosure, and EoP (Elevation of Privilege) risks.

9. **Zero-Knowledge Cryptographic Design:** Prevents Bitwarden (or an attacker) from [decrypting user vaults](https://bitwarden.com/resources/zero-knowledge-encryption).

10. **Annual Third-Party Security Audits:** [Mitigates risks arising from implementation flaws](https://bitwarden.com/help/is-bitwarden-audited/#third-party-security-audits).


## Project Board
[Software Assurance Project: To-Do](https://github.com/users/ysabum/projects/1)


## Team Reflection

Working on the Emergency Access and Secrets Manager features in Bitwarden helped us understand how important it is to look closely at how data moves through a system. Creating the DFD and doing the STRIDE analysis showed us where weaknesses can appear and why trust boundaries matter.

Additionally, reviewing Bitwarden’s documentation helped in connecting the threats in the model to the actual controls in the system, such as encryption, logging, and the waiting period. Noticing gaps like optional MFA for emergency contacts also helped in seeing how certain user settings can reduce security.

Overall, this assignment helped us develop a clearer view of how to analyze a feature, understand its risks, and match threats to real-world mitigations.