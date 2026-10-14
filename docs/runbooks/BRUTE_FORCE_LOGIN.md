# Runbook: BRUTE_FORCE_LOGIN

## 1. Description
Detects repeated failed authentication attempts originating from the same IP address within a short timeframe. This activity indicates an automated or password-guessing brute force attack attempting to guess user credentials.

- **Severity:** High
- **MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [5m]))
  ```
- **Threshold:** `>= 5` failures within a 5-minute sliding window.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Inspect the source IP address in the logs (`{container="tenantguard_api"} | json | ip="<IP>"`).
   - Check if the IP belongs to a known internal service, VPN gateway, NAT egress, or corporate IP range.
   - Determine whether a single user simply mistyped their password or if multiple users are targeted.
2. **Identify Scope:**
   - Query targeted usernames from that IP:
     ```logql
     sum by (username) (count_over_time({container="tenantguard_api"} | json | ip="<IP>" | event="AUTH_LOGIN_FAILED" [15m]))
     ```
   - Check if any login succeeded from this IP or for any of the targeted accounts during or after the attack window (`event="AUTH_LOGIN_SUCCESS"`).
3. **Qualify Impact:**
   - If no logins succeeded, the impact is confined to failed attempts and service noise.
   - If any login succeeded from the suspect IP, escalate immediately to account takeover incident procedures.

## 4. Immediate Containment
- **IP Blocking:** Add the offending IP address to the perimeter firewall or reverse proxy blocklist (e.g. iptables, cloud WAF, Nginx deny rule).
- **Rate Limiting:** Enforce strict per-IP rate limiting on `/auth/login` if not already enforced.
- **Account Protection:** If a specific account was heavily targeted, temporarily lock the account or force a password reset and session invalidation.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
