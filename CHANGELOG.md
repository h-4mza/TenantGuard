# Changelog — TenantGuard

Toutes les modifications notables apportées au projet **TenantGuard** sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/), et ce projet adhère au [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-10-15

### Ajouté
- **Bloc 7 — Finalisation & Portfolio :**
  - Durcissement de la CI DevSecOps : épinglage de `runs-on: ubuntu-24.04` sur les 6 jobs, épinglage strict des images Docker (`gitleaks:v8.30.1`, `trivy:0.76.0`) et migration des actions vers Node 24 avec SHAs vérifiés par l'API GitHub (`actions/checkout@v7.0.1`, `actions/setup-python@v7.0.0`, `anchore/sbom-action@v0.24.3`).
  - Inventaire exhaustif des secrets de l'historique Git et plan de purge documenté et testé localement dans [`docs/HISTORY_PURGE.md`](docs/HISTORY_PURGE.md) (0 leak Gitleaks, tests passants).
  - Étude de cas structurée pour portfolio dans [`docs/PORTFOLIO.md`](docs/PORTFOLIO.md) avec métriques réelles et sources vérifiables.
  - Script de démonstration autonome de bout en bout [`scripts/demo.sh`](scripts/demo.sh) avec validation d'infrastructure et affichage des alertes.
  - Politique de sécurité [`SECURITY.md`](SECURITY.md) et notes de version [`RELEASE_NOTES.md`](RELEASE_NOTES.md).

- **Bloc 6 — Simulation d'Incident & Réponse Opérationnelle :**
  - Scénario d'incident réaliste rejouable en 4 phases chronologiques [`scripts/run_incident.sh`](scripts/run_incident.sh).
  - Rapport d'investigation médico-légale LogQL [`docs/incident/INVESTIGATION.md`](docs/incident/INVESTIGATION.md).
  - Preuves réelles de confinement [`docs/incident/CONTAINMENT_EVIDENCE.md`](docs/incident/CONTAINMENT_EVIDENCE.md) (verrouillage de compte en base et rotation globale de clé JWT).
  - Post-mortem blameless [`docs/incident/POSTMORTEM.md`](docs/incident/POSTMORTEM.md) avec calcul du MTTD mesuré (46,5 secondes) et journal d'alertes réelles [`docs/incident/evidence/alerts_received.log`](docs/incident/evidence/alerts_received.log).
  - Runbooks de réponse à incident détaillés dans [`docs/runbooks/`](docs/runbooks/).

- **Bloc 5 — Détection des Menaces & Grafana Unified Alerting :**
  - Provisioning Infrastructure-as-Code des alertes Grafana dans `config/grafana/provisioning/alerting/` : 7 règles de détection évaluées chaque minute et mappées à MITRE ATT&CK (`BRUTE_FORCE_LOGIN`, `CREDENTIAL_STUFFING`, `CROSS_TENANT_ACCESS`, `UPLOAD_ANOMALY`, `TOKEN_ABUSE_SUSPECT`, `ACCOUNT_TAKEOVER_SUSPECT`, `EXFILTRATION_VOLUME`).
  - Tableau de bord de détection pré-provisionné `Detection Overview` (`tenantguard-detection-overview`).
  - Récepteur d'alertes webhook local (`tenantguard_alert_receiver`) sur port 8088.
  - Scripts de simulation d'attaque [`scripts/simulate_attacks.sh`](scripts/simulate_attacks.sh) et de vérification [`scripts/verify_detections.sh`](scripts/verify_detections.sh).

- **Bloc 4 — Observabilité & Audit Structuré :**
  - Stack d'observabilité complète dans `docker-compose.observability.yml` : Promtail 3.0.0, Loki 3.0.0, Grafana 11.0.0.
  - Logging d'audit JSON standardisé (`event`, `level`, `user_id`, `tenant_id`, `ip`, `details`) avec format standardisé et refus de sécurité journalisés.
  - Isolation réseau : liaison exclusive des ports d'observabilité sur `127.0.0.1`.

- **Bloc 3 — Pipeline DevSecOps & Remédiations de Sécurité :**
  - Pipeline GitHub Actions en 6 étapes : SAST (Semgrep), SCA (pip-audit), Secrets (Gitleaks), Build + Scan image (Trivy), DAST (OWASP ZAP Baseline), SBOM (Syft SPDX).
  - Remédiation de l'ensemble des vulnérabilités de la v0 : validation stricte de `JWT_SECRET` (min. 32 caractères), vérification d'expiration JWT (`verify_exp: True`), cloisonnement strict des routes de documents et de recherche RAG sur `current_user.tenant_id`, sécurisation des uploads (nom UUID, validation d'extension, limite 10 Mo, assainissement de chemin), et garde-fous de prompt LLM.
  - Exécution du conteneur applicatif en utilisateur non-root (UID 10001) et restriction CORS sur liste blanche.

### Modifié
- Harmonisation des dates d'incident et tri chronologique strict de la timeline dans la documentation d'incident.
- Matrice de remédiation et limites opérationnelles documentées dans [`KNOWN_ISSUES_V0.md`](KNOWN_ISSUES_V0.md).
- Refonte complète du [`README.md`](README.md) pour présenter l'architecture finale v1.0.

---

## [0.1.0] — 2026-10-12

### Ajouté
- Socle architectural de l'application SaaS multi-tenant TenantGuard (v0) :
  - API REST FastAPI avec documentation OpenAPI / Swagger.
  - Base de données relationnelle PostgreSQL 15 avec ORM SQLAlchemy.
  - Base de données vectorielle ChromaDB pour la recherche sémantique documentaire.
  - Service RAG avec intégration de Google Gemini et mock intégré pour tests locaux.
  - Seeding automatique de 3 tenants (`Acme Corp`, `CyberDyne Systems`, `Initech`) et 3 comptes de démonstration.
- Introduction délibérée de 8 vulnérabilités critiques pour audit pédagogique (faiblesse JWT, absence d'expiration, IDOR/BOLA cross-tenant, upload non restreint, fuite sémantique RAG, prompt injection, identifiants d'infrastructure codés en dur).
- Campagne de pentest offensive documentée dans `pentest/report.md` et `pentest/findings/`.
