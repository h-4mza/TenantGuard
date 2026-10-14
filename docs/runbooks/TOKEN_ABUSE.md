# Runbook: TOKEN_ABUSE

## 1. Description
Detects repeated API requests presenting expired or invalid JSON Web Tokens (`AUTH_TOKEN_EXPIRED`) from the same IP address within 5 minutes. This behavior suggests token replay attempts, compromised stale tokens being re-used by automated tools, or misconfigured API clients.

- **Severity:** Medium
- **MITRE ATT&CK:** [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_TOKEN_EXPIRED" [5m]))
  ```
- **Threshold:** `>= 5` expired token events from the same IP within 5 minutes.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Check if the IP corresponds to a known client application or background integration whose token refresh loop has failed.
   - Inspect the request path (e.g., `/documents`, `/rag/query`) to see what resource was being accessed.
2. **Identify Scope:**
   - Filter logs by the source IP:
     ```logql
     {container="tenantguard_api"} | json | ip="<IP>"
     ```
   - Check if the IP attempted other endpoints or transitioned to brute force / registration endpoints.
   - Identify whether the expired token belonged to an administrative or high-privilege account.
3. **Qualify Impact:**
   - Expired tokens are rejected with HTTP 401, preventing unauthorized state modification or data leakage.
   - If accompanied by successful authentication from the same IP using different credentials, investigate potential credential theft.

## 4. Immediate Containment
- **Client IP Throttling:** Throttle or block the offending IP address at the reverse proxy or API gateway.
- **Token Invalidation:** If a specific compromised token signature or jti is known, blacklist the token.
- **Client Notification:** Contact the account owner if legitimate integration credentials have expired without auto-renewal.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
