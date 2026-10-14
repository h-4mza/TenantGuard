# Runbook: CREDENTIAL_STUFFING

## 1. Description
Detects automated credential stuffing or password spraying where an attacker tests multiple distinct usernames from a single source IP address against the TenantGuard authentication endpoint within a 5-minute window.

- **Severity:** High
- **MITRE ATT&CK:** [T1110.004 - Brute Force: Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  count by (ip) (sum by (ip, username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [5m])))
  ```
- **Threshold:** `>= 5` distinct usernames with failed attempts from the same IP within 5 minutes.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Review the attacking IP against threat intelligence feeds, Tor exit nodes, and commercial proxy lists.
   - Confirm if requests show scripted headers, rapid timing, or random user agents.
2. **Identify Scope:**
   - Retrieve all distinct usernames targeted:
     ```logql
     sum by (username) (count_over_time({container="tenantguard_api"} | json | ip="<IP>" | event="AUTH_LOGIN_FAILED" [10m]))
     ```
   - Check if any targeted usernames exist in the TenantGuard user database.
   - Check whether any attempt resulted in `AUTH_LOGIN_SUCCESS` for any of the targeted accounts.
3. **Qualify Impact:**
   - If only non-existent or failed usernames were involved, impact is limited to scanning.
   - If any valid user account was breached, mark as active incident and identify any data accessed by that user.

## 4. Immediate Containment
- **IP Blocking:** Drop traffic from the attacker IP at the WAF / load balancer / reverse proxy layer.
- **Account Lock / Reset:** For valid usernames tested during the spray, force password changes and revoke existing JWT refresh/access tokens.
- **WAF Rules:** Activate bot protection / CAPTCHA challenge on the `/auth/login` endpoint.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1110.004: Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
