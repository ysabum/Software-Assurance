## 🧩 Review of Mitigations in the Bitwarden
Bitwarden implements nearly all expected mitigations derived from level1 DFD-based STRIDE threat analysis.

### ✔ Mitigations Confirmed in OSS Implementation

1. Strong Identity Verification (MFA & Trusted Contact Enrollment)

    Bitwarden supports multiple forms of MFA (https://bitwarden.com/help/setup-two-step-login/)including FIDO2, Duo, authenticator apps, email-based codes, and YubiKey OTP. This mitigates spoofing risks for Trusted Emergency Contacts.

2. Enforced Waiting Period & Approval Workflow

    The Emergency Access workflow includes a configurable waiting period and explicit approval or denial steps.
    Documentation: https://bitwarden.com/help/emergency-access/#trusted-emergency-contacts

3. End-to-End Encryption on All Vault and Emergency Access Data

    Bitwarden uses AES-256-CBC, RSA-2048, and PBKDF2-HMAC-SHA256 for encryption and key derivation.
    Source: https://bitwarden.com/help/bitwarden-security-white-paper/#hashing-key-derivation-and-encryption

    These controls mitigate tampering, disclosure, and EoP (Elevation of Privilege) risks.
    
4. Immutable Audit Logging

    Event logs capture all emergency access attempts, approval/denial actions, and MFA events.
    Documentation: https://bitwarden.com/help/event-logs/

5. Notification of Owner for Every Access Request

    Bitwarden notifies the vault owner for each emergency access request(https://bitwarden.com/help/emergency-access/).

6. Zero-Knowledge Cryptographic Design

    Prevents Bitwarden (or an attacker) from decrypting user vaults (https://bitwarden.com/resources/zero-knowledge-encryption/).

7. Annual Third-Party Security Audits

    Mitigates risks arising from implementation flaws (https://bitwarden.com/help/is-bitwarden-audited/#third-party-security-audits)

Together, these directly map to the STRIDE threats identified in  Level-1 DFD [TMT report](https://github.com/ysabum/Software-Assurance/blob/main/images/DFD/emergencyContactAccess/trusted_contact_dfd1_report.htm) (spoofing, tampering, repudiation, disclosure, DoS, EoP).

## ⚠️ Identified Gaps and Areas for Improvement

After comparing the DFD-based threat analysis with Bitwarden’s official documentation, we identified two key gaps.

1. MFA for Emergency Contacts Is Optional

Emergency contacts do not need a paid subscription, which means they are not required to enable MFA.
This creates a policy-level gap where the emergency contact may authenticate with weaker security than the vault owner, increasing the chance of spoofing.

2. Waiting Period Is Fully User-Configurable

The vault owner sets the waiting period length freely.
Users may choose an insecurely short waiting period, weakening the protection intended by this control.

Documentation confirms this flexibility: https://bitwarden.com/help/emergency-access/

These two gaps are policy issues rather than architectural flaws.

## Swetha's Reflection

Working on the Emergency Access feature in Bitwarden helped me understand how important it is to look closely at how data moves through a system. Creating the DFD and doing the STRIDE analysis showed me where weaknesses can appear and why trust boundaries matter.

Reviewing Bitwarden’s documentation helped me connect the threats in the model to the actual controls in the system, such as encryption, logging, and the waiting period. Noticing gaps like optional MFA for emergency contacts also helped me see how certain user settings can reduce security.

Overall, this assignment helped me develop a clearer view of how to analyze a feature, understand its risks, and match threats to real-world mitigations