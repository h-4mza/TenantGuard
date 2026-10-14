# Runbook: UPLOAD_ABUSE

## 1. Description
Detects repeated document upload failures (`UPLOAD_REJECTED`) by a single user within a 10-minute period. This typically indicates attempts to bypass file upload filters, upload disallowed file extensions (e.g., `.exe`, `.sh`, `.py`), or trigger deserialization / parser exploits.

- **Severity:** Medium
- **MITRE ATT&CK:** [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

## 2. Trigger
- **LogQL Expression:**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event="UPLOAD_REJECTED" [10m]))
  ```
- **Threshold:** `>= 3` upload rejections for the same user within 10 minutes.

## 3. Triage in 3 Steps
1. **Verify Legitimacy:**
   - Review the rejection reasons in audit logs (`filename`, `file_type`, `error` or message fields).
   - Check if an honest user repeatedly uploaded an unsupported document format (e.g., `.docx` instead of `.pdf` / `.txt`).
2. **Identify Scope:**
   - Extract all upload attempts from that user:
     ```logql
     {container="tenantguard_api"} | json | user_id="<USER_ID>" | event =~ "DOCUMENT_UPLOAD|UPLOAD_REJECTED"
     ```
   - Check if any malicious upload bypassed validation (`DOCUMENT_UPLOAD` event following rejected attempts).
   - Inspect filenames for directory traversal sequences (e.g. `../../`), double extensions (`.pdf.exe`), or shell payload names.
3. **Qualify Impact:**
   - If files were blocked by the validation layer, impact is restricted to blocked requests.
   - If any suspect file was stored or parsed by the RAG embedding pipeline, isolate the file and check for code execution artifacts.

## 4. Immediate Containment
- **User Suspension:** Temporarily suspend document upload permissions for the user account.
- **File Quarantine:** Delete or quarantine any recently uploaded documents from that tenant's document store.
- **Review Content:** Inspect any successful uploads in that tenant's storage bucket or directory.

## 5. References & Dashboards
- **Grafana Dashboard:** [TenantGuard Detection Overview](/d/tenantguard-detection-overview)
- **MITRE ATT&CK:** [Technique T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
