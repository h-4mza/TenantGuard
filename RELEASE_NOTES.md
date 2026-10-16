# Release Notes — TenantGuard v1.0.0

**Date de publication :** 15 octobre 2026  
**Branche cible :** `main`  
**Statut du tag :** En attente de validation explicite de l'utilisateur (ne pas poser sans confirmation).  

---

## 🌟 Vue d'ensemble de la version 1.0.0

La version **1.0.0** marque l'aboutissement du cycle complet de sécurisation, d'observabilité et de détection opérationnelle de la plateforme SaaS multi-tenant **TenantGuard**.

Partant d'une base délibérément vulnérable (v0) conçue pour la pédagogie et l'audit offensif ([`pentest/report.md`](pentest/report.md)), cette version apporte une architecture durcie en profondeur, un pipeline DevSecOps automatisé, une stack d'observabilité complète (Promtail, Loki, Grafana) avec 7 règles d'alerte unifiées mappées à MITRE ATT&CK, et un dossier d'incident médico-légal complet (MTTD mesuré à 46,5 secondes).

---

## 🚀 Principales Nouveautés & Réalisations

### 1. Remédiation Intégrale des Vulnérabilités (v0 → v1.0)
- **FINDING-01 & FINDING-08 (Secrets & Infrastructure) :** Exigence d'une clé `JWT_SECRET` cryptographiquement forte (min. 32 caractères / 256 bits d'entropie) validée au démarrage de l'API. Élimination complète des mots de passe par défaut dans le code et les fichiers Compose.
- **FINDING-02 (Gestion des Sessions) :** Rétablissement de la vérification stricte de l'expiration des jetons JWT (`verify_exp: True`) avec rejet immédiat en HTTP 401 et journalisation d'audit `AUTH_LOGIN_FAILED` (`token_expired`).
- **FINDING-03 & FINDING-04 (Isolation Multi-Tenant IDOR / BOLA) :** Cloisonnement strict des routes de documents et de métadonnées dérivé exclusivement du claim `tenant_id` du JWT authentifié. Les tentatives d'accès inter-tenants renvoient un code HTTP 404 neutre et déclenchent l'événement d'audit `DOCUMENT_ACCESS_DENIED`.
- **FINDING-05 (Sécurisation des Téléversements) :** Filtrage d'extension par liste blanche (`.txt`, `.pdf`, `.docx`, `.csv`), quota de taille maximal de 10 Mo, assainissement des noms (`os.path.basename`) et stockage sous identifiants UUID aléatoires pour neutraliser tout *Path Traversal*.
- **FINDING-06 & FINDING-07 (Sécurisation RAG & Guardrails LLM) :** Filtrage vectoriel ChromaDB obligatoire et non surchargeable (`where={"tenant_id": ...}`), encapsulage du prompt utilisateur dans des délimiteurs stricts et directives système interdisant l'extraction de secrets.

### 2. Pipeline DevSecOps Robuste (GitHub Actions)
- Exécution sur environnement figé **`runs-on: ubuntu-24.04`** (anticipation de la migration Ubuntu 26 d'octobre 2026).
- 6 jobs exécutés en parallèle :
  - **SAST :** Semgrep avec règles OWASP Top 10 (zéro finding bloquant).
  - **SCA :** pip-audit pour les dépendances Python.
  - **Secrets :** Gitleaks v8.30.1 épinglé (zéro leak dans l'arbre de travail).
  - **Container Scan :** Trivy 0.76.0 épinglé sur l'image Docker (`--severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`).
  - **DAST :** OWASP ZAP Baseline automatisé (informatif).
  - **SBOM :** Syft v0.24.3 générant un inventaire SPDX-JSON complet (171 paquets).
- Actions GitHub migrées vers Node 24 et épinglées par SHA de commit vérifiés (`actions/checkout@v7.0.1`, `actions/setup-python@v7.0.0`, `anchore/sbom-action@v0.24.3`).

### 3. Observabilité Structurée & Détection des Menaces
- Stack conteneurisée complète (`docker-compose.observability.yml`) : Promtail 3.0.0, Loki 3.0.0, Grafana 11.0.0.
- Journalisation d'audit JSON standardisée (`event`, `level`, `user_id`, `tenant_id`, `ip`).
- 7 règles Grafana Unified Alerting provisionnées en code et évaluées chaque minute :
  - `BRUTE_FORCE_LOGIN` (MITRE T1110)
  - `CREDENTIAL_STUFFING` (MITRE T1110.004)
  - `CROSS_TENANT_ACCESS` (MITRE T1078 / T1190)
  - `UPLOAD_ABUSE` (MITRE T1105)
  - `TOKEN_ABUSE` (MITRE T1528)
  - `ACCOUNT_TAKEOVER_SUSPECT` (MITRE T1110)
  - `EXFILTRATION_VOLUME` (MITRE T1530)
- Tableau de bord pré-provisionné `Detection Overview` et récepteur d'alertes webhook local sur port 8088.

### 4. Réponse à Incident & Post-Mortem Médico-Légal
- Scénario d'incident réaliste rejouable en 4 phases chronologiques ([`scripts/run_incident.sh`](scripts/run_incident.sh)).
- **Temps Moyen de Détection (MTTD) mesuré : 46,5 secondes**.
- Preuves réelles de confinement vérifiées (verrouillage utilisateur en base et rotation globale de `JWT_SECRET`).
- Post-mortem blameless complet ([`docs/incident/POSTMORTEM.md`](docs/incident/POSTMORTEM.md)) et 7 runbooks opérationnels ([`docs/runbooks/`](docs/runbooks/)).

### 5. Traçabilité des Secrets Git & Démonstration Autonome
- Inventaire complet de l'historique Git et acceptation des risques documentée avec baseline Gitleaks ([`docs/HISTORY_RISK_ACCEPTANCE.md`](docs/HISTORY_RISK_ACCEPTANCE.md)).
- Script de démonstration autonome en une commande ([`scripts/demo.sh`](scripts/demo.sh)).

---

## 📋 Commande pour Activer la Version (Post-Validation)

Après validation formelle de l'utilisateur :

```bash
git tag -a v1.0 -m "Release v1.0 - Secure Multi-Tenant RAG with Observability & Detection"
git push origin v1.0
```
