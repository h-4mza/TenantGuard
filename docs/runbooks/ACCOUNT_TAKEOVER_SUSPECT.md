# Runbook: ACCOUNT_TAKEOVER_SUSPECT

## 1. Description
Detects a successful authentication event (`AUTH_LOGIN_SUCCESS`) occurring within 10 minutes following repeated failed authentication attempts (`AUTH_LOGIN_FAILED` >= 3) against the exact same username. This pattern strongly indicates a successful brute force, password spray, or compromised account takeover.

- **Severity:** Critical
- **MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  (sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [10m])) >= 3) and (sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_SUCCESS" [10m])) >= 1)
  ```
- **Threshold:** `>= 3` failed logins and `>= 1` successful login for the same username within 10 minutes.
- **Limite technique LogQL :** La règle compare deux compteurs sur la même fenêtre de 10 min, sans garantir l'ordre ; un succès antérieur aux échecs la déclenche aussi.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Compare the IP address of the failed login attempts with the IP address of the successful login event:
     ```logql
     {container="tenantguard_api"} | json | username="<USERNAME>"
     ```
   - If the IPs match and represent an employee or client who forgot their password before remembering it, check geolocation and user confirmation.
   - If the successful IP differs from the failed attempts, or originates from an anomalous ASN/country, treat as confirmed account compromise.
2. **Identify Scope:**
   - Analyze all actions taken by this user session post-login:
     - Document views (`DOCUMENT_VIEW`), downloads (`DOCUMENT_DOWNLOAD`), deletions (`DOCUMENT_DELETE`), or RAG queries (`RAG_QUERY`).
   - Check if any configuration or user permissions were modified.
3. **Qualify Impact:**
   - Determine whether sensitive multi-tenant documents were viewed or exported.
   - Assess data exposure level and identify which tenant environment was accessed.

## 4. Immediate Containment
- **Session Revocation:** Immediately revoke the newly issued JWT token and terminate all active sessions for the user.
- **Account Lock:** Lock the compromised account to prevent further logins.
- **Password Reset:** Issue a mandatory password reset via an out-of-band communication channel (e.g., direct email to registered address).
- **IP Blocking:** Blacklist the IP address that performed the successful login.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
