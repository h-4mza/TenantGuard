# Runbook: CROSS_TENANT_ACCESS

## 1. Description
Detects repeated attempts by an authenticated user to access or manipulate documents belonging to another tenant (`DOCUMENT_ACCESS_DENIED`). This indicates potential IDOR (Insecure Direct Object Reference) or BOLA (Broken Object Level Authorization) probing / exploitation.

- **Severity:** Critical
- **MITRE ATT&CK:** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) / [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event="DOCUMENT_ACCESS_DENIED" [5m]))
  ```
- **Threshold:** `>= 3` denied cross-tenant document requests by the same user within 5 minutes.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Check the `user_id` and corresponding `tenant_id` associated with the alert.
   - Inspect requested `document_id` values to see if sequential enumeration (e.g. 1, 2, 3...) or random GUIDs were tested.
   - Determine if the user is a normal client, an internal QA tester, or an adversarial account.
2. **Identify Scope:**
   - Extract the full audit trail of the user:
     ```logql
     {container="tenantguard_api"} | json | user_id="<USER_ID>"
     ```
   - Check whether any cross-tenant request returned HTTP 200 (`DOCUMENT_VIEW` or `DOCUMENT_DOWNLOAD`) rather than 403/404.
   - Identify which target tenants' document IDs were probed.
3. **Qualify Impact:**
   - If all requests were successfully blocked by TenantGuard's multi-tenant isolation, data confidentiality remains intact.
   - If any cross-tenant read or modification succeeded, initiate data breach protocol and notify affected tenants.

## 4. Immediate Containment
- **User Suspension:** Immediately suspend or disable the offending user account in the database.
- **Session Revocation:** Invalidate all active tokens / sessions for that user.
- **Client IP Restriction:** Temporarily block the client IP address associated with the user sessions.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) / [Technique T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
