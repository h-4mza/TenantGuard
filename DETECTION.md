# TenantGuard Detection & Alerting Engineering

This document specifies the detection rules, LogQL implementations, alerting pipeline, and attack simulation suite provisioned for the TenantGuard multi-tenant platform.

---

## 1. Detection Rules Matrix

All detection rules are provisioned as code in `config/grafana/provisioning/alerting/rules.yml` under the **Grafana Unified Alerting** engine.

| Règle | Événement source | Seuil | MITRE ATT&CK | Sévérité | Faux positifs connus | Réaction attendue |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **BRUTE_FORCE_LOGIN** | `AUTH_LOGIN_FAILED` | $\ge 5$ échecs en 5 min par `ip` | [T1110](https://attack.mitre.org/techniques/T1110/) | High | Utilisateur légitime ayant oublié son mot de passe ; test de charge interne. | Blocage temporaire IP au niveau reverse proxy / WAF ; notification utilisateur si compte ciblé. |
| **CREDENTIAL_STUFFING** | `AUTH_LOGIN_FAILED` | $\ge 5$ usernames distincts en 5 min par `ip` | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | High | Scanner de vulnérabilité interne autorisé ; scanner de santé d'orchestrateur. | Blocage immédiat de l'IP source au WAF ; révocation de sessions actives pour les comptes existants testés. |
| **CROSS_TENANT_ACCESS** | `DOCUMENT_ACCESS_DENIED` | $\ge 3$ refus en 5 min par `user_id` | [T1078](https://attack.mitre.org/techniques/T1078/) / [T1190](https://attack.mitre.org/techniques/T1190/) | Critical | Lien hypertexte obsolète ou partagé par erreur entre collaborateurs de tenants différents. | Suspension immédiate du compte utilisateur ; révocation des jetons JWT ; audit forensique des accès du tenant cible. |
| **UPLOAD_ABUSE** | `UPLOAD_REJECTED` | $\ge 3$ rejets en 10 min par `user_id` | [T1105](https://attack.mitre.org/techniques/T1105/) | Medium | Utilisateur tentant d'uploader des formats bureautiques non supportés (.docx au lieu de .pdf). | Désactivation temporaire des droits d'upload de l'utilisateur ; purge des fichiers suspects éventuellement mis en quarantaine. |
| **TOKEN_ABUSE** | `AUTH_TOKEN_EXPIRED` | $\ge 5$ tokens expirés en 5 min par `ip` | [T1528](https://attack.mitre.org/techniques/T1528/) | Medium | Client API ou script d'intégration avec boucle de rafraîchissement de token défaillante. | Limitation de débit / throttling de l'IP ; alerte envoyée à l'administrateur de l'intégration concernée. |
| **ACCOUNT_TAKEOVER_SUSPECT** | `AUTH_LOGIN_FAILED` + `AUTH_LOGIN_SUCCESS` | $\ge 3$ échecs suivis d'un succès en 10 min pour un même `username` | [T1110](https://attack.mitre.org/techniques/T1110/) | Critical | Utilisateur trouvant enfin son mot de passe après plusieurs essais infructueux sur la même machine. | Révocation immédiate de la session nouvellement ouverte ; verrouillage préventif du compte ; réinitialisation de mot de passe hors-bande. |
| **EXFILTRATION_VOLUME** | `DOCUMENT_DOWNLOAD` ou `DOCUMENT_VIEW` | $\ge 20$ accès en 5 min par `user_id` | [T1530](https://attack.mitre.org/techniques/T1530/) | Medium | Synchronisation en masse ou sauvegarde programmée par un administrateur de tenant légitime. | Révocation de session ; limitation de bande passante ; prise de contact avec le point focal de sécurité du tenant. |

---

## 2. LogQL Implementation Details

Audit logs emitted by TenantGuard are parsed at query time via `| json`. Only `container`, `job`, `event`, and `level` are indexed as Loki labels to prevent high cardinality explosions. All fine-grained identifiers (`user_id`, `ip`, `username`, `tenant_id`) are parsed dynamically.

### A. Distinct Count Implementation (CREDENTIAL_STUFFING)
LogQL does not provide a native `distinct_count_over_time()` function. To count distinct usernames targeted by a single IP address without cardinality issues:
```logql
count by (ip) (
  sum by (ip, username) (
    count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [5m])
  )
)
```
1. **Inner aggregation:** `sum by (ip, username) (...)` groups events by each distinct `(ip, username)` tuple having at least one failure in the 5-minute window.
2. **Outer aggregation:** `count by (ip) (...)` counts the number of discrete series remaining per IP. This yields the exact distinct username count per source IP.

### B. Multi-Event Correlation Implementation (ACCOUNT_TAKEOVER_SUSPECT)
To detect an attack where multiple failures precede a success on the same account within a 10-minute window, LogQL's binary vector matching operator `and` is utilized:
```logql
(sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [10m])) >= 3)
and
(sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_SUCCESS" [10m])) >= 1)
```
- The left vector identifies usernames experiencing $\ge 3$ failed logins.
- The right vector identifies usernames experiencing $\ge 1$ successful login.
- The `and` operator matches series having identical `username` labels and emits an alert series only when both conditions are satisfied simultaneously.

---

## 3. Provisioned Alerting Architecture

```
                  ┌──────────────────────┐
                  │   TenantGuard API    │
                  │ (Structured JSON Log)│
                  └──────────┬───────────┘
                             │ stdout
                             ▼
                  ┌──────────────────────┐
                  │       Promtail       │
                  │   (Docker SD + JSON) │
                  └──────────┬───────────┘
                             │ push
                             ▼
                  ┌──────────────────────┐
                  │         Loki         │
                  │ (Log Storage / LogQL)│
                  └──────────┬───────────┘
                             │ poll (1m)
                             ▼
                  ┌──────────────────────┐
                  │   Grafana Alerting   │
                  │ (Rules, Policies, CP)│
                  └──────────┬───────────┘
                             │ webhook
                             ▼
                  ┌──────────────────────┐
                  │    Alert Receiver    │
                  │ (HTTP stdout logger) │
                  └──────────────────────┘
```

- **Rules Provisioning:** `config/grafana/provisioning/alerting/rules.yml`
- **Contact Points:** `config/grafana/provisioning/alerting/contactpoints.yml` (routes alerts to `http://alert-receiver:8080/alerts`)
- **Notification Policies:** `config/grafana/provisioning/alerting/policies.yml` (group wait 5s, repeat interval 10s)
- **Local Webhook Receiver:** `config/alert_receiver/receiver.py` (running as service `alert-receiver` in `docker-compose.observability.yml`, bound to `127.0.0.1:8088`)

---

## 4. Attack Simulation & Verification

An automated test suite reproduces the 7 attack scenarios using `curl` against the TenantGuard API.

### Replay Command
To run the attack simulation and verify that all 7 detection rules enter the `Firing` state:
```bash
bash scripts/verify_detections.sh
```

### Manual Trigger
Alternatively, run the raw simulation script:
```bash
bash scripts/simulate_attacks.sh
```
and query the Grafana Alerting API:
```bash
curl -u admin:${GRAFANA_ADMIN_PASSWORD} http://127.0.0.1:3000/api/prometheus/grafana/api/v1/alerts
```

---

## 5. Security Runbooks

Each detection rule links directly to an actionable runbook located in `docs/runbooks/`:
- [`BRUTE_FORCE_LOGIN.md`](docs/runbooks/BRUTE_FORCE_LOGIN.md)
- [`CREDENTIAL_STUFFING.md`](docs/runbooks/CREDENTIAL_STUFFING.md)
- [`CROSS_TENANT_ACCESS.md`](docs/runbooks/CROSS_TENANT_ACCESS.md)
- [`UPLOAD_ABUSE.md`](docs/runbooks/UPLOAD_ABUSE.md)
- [`TOKEN_ABUSE.md`](docs/runbooks/TOKEN_ABUSE.md)
- [`ACCOUNT_TAKEOVER_SUSPECT.md`](docs/runbooks/ACCOUNT_TAKEOVER_SUSPECT.md)
- [`EXFILTRATION_VOLUME.md`](docs/runbooks/EXFILTRATION_VOLUME.md)
