# Runbook: EXFILTRATION_VOLUME

## 1. Description
Detects an unusually large volume of document read operations (`DOCUMENT_DOWNLOAD` or `DOCUMENT_VIEW`) by a single user within a 5-minute window. This indicates possible mass exfiltration of tenant intellectual property, bulk scraping, or unauthorized data archiving by a compromised or malicious insider account.

- **Severity:** Medium
- **MITRE ATT&CK:** [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW" [5m]))
  ```
- **Threshold:** `>= 20` document view or download operations by the same user within 5 minutes.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Identify the user (`user_id`) and their tenant role.
   - Contact the user or tenant administrator to verify whether a planned bulk export, report generation, or document sync was scheduled.
2. **Identify Scope:**
   - Retrieve all document IDs accessed during the burst window:
     ```logql
     {container="tenantguard_api"} | json | user_id="<USER_ID>" | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW"
     ```
   - Verify whether all accessed documents strictly belonged to the user's assigned tenant.
   - Calculate total volume (bytes/document count) exfiltrated.
3. **Qualify Impact:**
   - Determine the data classification of accessed documents (PII, financial records, confidential business data).
   - If documents were accessed outside normal business hours or from an unrecognized IP, classify as confirmed exfiltration.

## 4. Immediate Containment
- **Session Revocation:** Terminate all active sessions for the user account.
- **Access Throttling:** Temporarily restrict or revoke document download permissions for the user account.
- **Audit Preservation:** Export and archive all audit logs related to the incident for forensic review.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1530: Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
