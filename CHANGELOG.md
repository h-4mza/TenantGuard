# Changelog — TenantGuard

Toutes les modifications notables apportées au projet **TenantGuard** sont consignées dans ce fichier.
Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/), et ce projet adhère au [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-10-15

### Ajouté
- **Bloc 7 — Finalisation & Portfolio :**
  - Durcissement de la CI DevSecOps : épinglage de `runs-on: ubuntu-24.04` sur les 6 jobs, épinglage strict des images Docker (`gitleaks:v8.30.1`, `trivy:0.76.0`) et migration des actions vers Node 24 avec SHAs vérifiés par l'API GitHub (`actions/checkout@v7.0.1`, `actions/setup-python@v7.0.0`, `anchore/sbom-action@v0.24.3`).
  - Inventaire exhaustif des secrets de l'historique Git et acceptation des risques documentée dans [`docs/HISTORY_RISK_ACCEPTANCE.md`](docs/HISTORY_RISK_ACCEPTANCE.md) avec baseline Gitleaks opérationnelle (0 leak Gitleaks).
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
  - Provisioning Infrastructure-as-Code des alertes Grafana dans `config/grafana/provisioning/alerting/` : 7 règles de détection évaluées chaque minute et mappées à MITRE ATT&CK (`BRUTE_FORCE_LOGIN`, `CREDENTIAL_STUFFING`, `CROSS_TENANT_ACCESS`, `UPLOAD_ABUSE`, `TOKEN_ABUSE`, `ACCOUNT_TAKEOVER_SUSPECT`, `EXFILTRATION_VOLUME`).
  - Tableau de bord de détection pré-provisionné `Detection Overview` (`tenantguard-detection-overview`).
  - Récepteur d'alertes webhook local (`tenantguard_alert_receiver`) sur port 8088.
  - Scripts de simulation d'attaque [`scripts/simulate_attacks.sh`](scripts/simulate_attacks.sh) et de vérification [`scripts/verify_detections.sh`](scripts/verify_detections.sh).

- **Bloc 4 — Observabilité & Audit Structuré :**
  - Stack d'observabilité complète dans `docker-compose.observability.yml` : Promtail 3.0.0, Loki 3.0.0, Grafana 11.0.0.
  - Logging d'audit JSON standardisé (`event`, `level`, `user_id`, `tenant_id`, `ip`, `details`) avec format standardisé et refus de sécurité journalisés.
  - Isolation réseau : liaison exclusive des ports d'observabilité sur `127.0.0.1`.

- **Bloc 3 — Pipeline DevSecOps & Remédiations de Sécurité :**
  - Pipeline GitHub Actions en 6 étapes : SAST (Semgrep), SCA (pip-audit), Secrets (Gitleaks), Build + Scan image (Trivy), DAST (OWASP ZAP Baseline), SBOM (Syft SPDX).
  - Remédiation intégrale des 8 vulnérabilités documentées lors de l'audit offensif initial (v0) :
    - **FINDING-01 & FINDING-08 (Clé JWT faible & secrets codés en dur) :** Suppression de tout fallback par défaut. Validation stricte au démarrage dans `app/auth.py` (`RuntimeError` si absent, inférieur à 32 caractères ou chaîne de placeholder). Retrait des valeurs de repli dans `docker-compose.yml` et documentation des commandes de génération cryptographique (`openssl rand -hex 32`).
    - **FINDING-02 (Vérification d'expiration JWT) :** Suppression de `options={"verify_exp": False}` dans `app/auth.py` ; capture explicite de `jwt.ExpiredSignatureError` retournant un statut `401 Unauthorized` avec `WWW-Authenticate: Bearer`.
    - **FINDING-03 & FINDING-04 (Cloisonnement BOLA / IDOR sur les documents) :** Retrait du paramètre client `tenant_id` sur toutes les routes de `app/routes/documents.py`. Forçage de `target_tenant_id = current_user.tenant_id` à l'upload. Filtrage strict par tenant au listage (`Document.tenant_id == current_user.tenant_id`) et consultation unitaire avec double clause SQL. Réponse systématique par `404 Not Found` (au lieu de `403`) pour éliminer tout oracle d'énumération inter-tenants.
    - **FINDING-05 (Traversée de répertoire & contrôle d'upload) :** Assainissement strict du nom de fichier (`os.path.basename` + regex alphanumérique) ; stockage sous UUID v4 aléatoire (`uuid4()_nom`) éliminant les collisions et l'écrasement ; validation stricte par liste blanche d'extensions (`.txt`, `.pdf`, `.docx`, `.md` avec rejet `400`) ; contrôle du volume maximal fixé à 10 Mo avec rejet `413 Payload Too Large`.
    - **FINDING-06 (Fuite de données cross-tenant dans la recherche RAG) :** Suppression du champ `tenant_id` du modèle Pydantic client `RAGQueryRequest`. Paramètre `tenant_id` rendu strictement obligatoire dans `rag_service.retrieve()` avec validation de type (`int > 0`) et application systématique du filtre `where={"tenant_id": tenant_id}` dans ChromaDB.
    - **FINDING-07 (Atténuation de l'injection de prompt) :** Directives système transmises via le paramètre natif `system_instruction` de l'API Gemini ; délimitation structurelle stricte via balises XML (`<context>` et `<user_query>`) ; consignes défensives ordonnant d'ignorer toute instruction trouvée dans les documents.
    - *Analyse d'atténuation :* L'injection de prompt est traitée par défense en profondeur (absence de séparation physique code/données dans l'architecture LLM, nature probabiliste des modèles). L'isolation vectorielle en amont (FINDING-06) constitue le rempart absolu garantissant qu'aucun vecteur étranger n'est chargé en mémoire, limitant l'impact maximal aux données du tenant de l'attaquant.
  - Exécution du conteneur applicatif en utilisateur non-root (UID 10001) et restriction CORS sur liste blanche.
  - Suite de tests unitaires et d'intégration automatisés validant chaque correctif.

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
