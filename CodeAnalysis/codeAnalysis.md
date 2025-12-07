## Manual Code Review
Files Analyzed:

-  libs/common/src/services/api.service.ts
-  libs/key-management-ui/src/emergency-access/emergency-access-trust.component.ts
-  src/Api/Auth/Controllers/EmergencyAccessController.cs
-  src/Core/Auth/Services/EmergencyAccess/EmergencyAccessService.cs

### [CWE-640: Weak Account Recovery Mechanism](https://cwe.mitre.org/data/definitions/640.html)

**Description:** The product contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak. 
  
**Code Observations** 

Token creation uses expiration but lacks single-use tracking:
```
tokenable.ExpirationDate = DateTime.UtcNow.AddHours(_globalSettings.OrganizationInviteExpirationHours);
```
(from EmergencyAccessService.SendInviteAsync)


Takeover does not require re-authentication:
```
await PasswordAsync(emergencyAccess, granteeUser, model);
```
(from EmergencyAccessController.Takeover)


The PasswordAsync method in EmergencyAccessService directly resets the vault owner’s password:
```
public async Task PasswordAsync(EmergencyAccess ea, User grantee, EmergencyAccessPasswordRequestModel model)
{
    user.PasswordHash = model.NewMasterPasswordHash;
    user.KeyEncrypted = model.NewKey;
}
```
There is no call to TOTP verification, WebAuthn, or any form of strong re-authentication.

Emergency Access uses a well-defined workflow involving invite, acceptance, confirmation, waiting period, and approval.Recovery tokens include identity binding (email + EmergencyAccessId) and have an expiration window.

Despite this, several weaknesses remain:

 - Takeover actions do not require recent re-authentication (no TOTP, WebAuthn, or password challenge).

 -  Recovery tokens are not single-use and are not tracked server-side after consumption.

 - No feature-specific rate limiting exists for recovery or takeover operations.

 - Critical actions are not logged for auditing.


The overall recovery design is strong, but missing second-layer protections. Adding re-auth, token invalidation, and detailed logging would significantly improve resistance to misuse.

### [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

**Description:** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

There are no audit logs in any part of Emergency Access.Examples of high-impact actions that generate no logs:
```
await ApproveAsync(...);
await RejectAsync(...);
await TakeoverAsync(...);
await PasswordAsync(...);
```

Even failed or invalid recovery attempts leave no trace.
Missing logs for invite acceptance, recovery initiation, approvals / rejections, takeover attempts, password resets via recovery

No correlation IDs or tracking for suspicious repeated actions.

This is a significant gap. Recovery mechanisms require detailed auditing, and none exists in this module.
### [CWE-642: External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

Emergency Access relies heavily on IDs and state transitions. If an attacker could manipulate those IDs, they could push the system into the wrong state.

All Emergency Access mutations are routed through EmergencyAccessService.

The service validates:

- whether the caller is the grantor or grantee,
- whether the Emergency Access entry is in the correct status,
- whether the requested action is allowed from that state.

No alternate or direct repository paths were found that bypass these checks.

This CWE is well-handled; ID-based state manipulation is not possible in the current design.

## Automated Code Review
I used Semgrep CLI to scan the Bitwarden clients repository.
Semgrep analyzed more than six thousand TypeScript, JavaScript, and HTML files and reported 18 issues, mainly in two categories:

### Possible Command Injection in Build Scripts (CWE-78)

Semgrep flagged several build and packaging scripts that use execSync() with values that could become unsafe if they were ever influenced by external input.

Files Involved

- apps/desktop/desktop_native/build.js
- apps/desktop/scripts/after-pack.js
- apps/web/scripts/optimize.js

Example Code
```
child_process.execSync(`npm run build -- ${targetArg}`, { stdio: "inherit" });
```
If targetArg or similar variables ever came from untrusted input, they could allow command injection.
Right now these scripts are internal and used only in development builds, so the practical risk is low.

### Possible XSS in HTML Templates (CWE-79)

Semgrep also warned about several HTML templates where dynamic values were placed directly into href attributes.
Example Code
```
<a href="{{ i.url }}">View</a>
```
Files Involved

- Billing and subscription pages
- Billing history components
- Report components

If the url or pdfUrl variables ever contained a value like javascript:alert(1), it could trigger XSS.
In practice these URLs come from trusted internal sources, but Semgrep reports them because the pattern can be risky in general.

## Reflection:
This assignment helped me understand what it really means to evaluate software for security. I learned how important it is to review the entire workflow instead of focusing only on individual functions. While examining the Emergency Access feature, I realized how missing pieces like re-authentication or proper logging can introduce real risks, even when the rest of the design seems secure.

I also learned how to match specific code behavior to CWE definitions and how to think more like a security reviewer. Automated scanning tools were helpful for spotting surface-level issues, but the deeper logic flaws only became clear through manual inspection. It also became obvious why the client should only handle basic UI interactions and why all critical checks must happen on the server. Finally, I gained a better appreciation for logging, since it plays a key role in tracking misuse and maintaining accountability.

Overall, this assignment made me more confident in reading code with a security mindset and understanding how secure design works in practice.