# TenantGuard 🛡️ — Application SaaS Multi-Tenant Volontairement Vulnérable (v0)

[![Phase](https://img.io/badge/phase-v0_vulnerable-critical.svg)](#)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![ChromaDB](https://img.shields.io/badge/vector_db-ChromaDB-orange.svg)](https://www.trychroma.com/)
[![PostgreSQL](https://img.shields.io/badge/db-PostgreSQL_15-336791.svg)](https://www.postgresql.org/)

> ⚠️ **AVERTISSEMENT DE SÉCURITÉ IMPORTANT**  
> Ce projet est un **projet pédagogique de cybersécurité** (portfolio pour candidature en stage de fin d'études).  
> **Cette version v0 est VOLONTAIREMENT VULNÉRABLE.**  
> Elle contient des failles de sécurité critiques conçues pour être exploitées, corrigées, puis monitorées dans le cadre de simulations d'incident.  
> **NE JAMAIS DÉPLOYER CETTE APPLICATION DANS UN ENVIRONNEMENT DE PRODUCTION.**  
> Consultez le fichier [KNOWN_ISSUES_V0.md](file:///C:/Users/HP/Desktop/TenantGuard/KNOWN_ISSUES_V0.md) pour la liste exhaustive des vulnérabilités volontairement introduites.

---

## 🎯 Contexte & Objectifs du Projet

**TenantGuard** illustre le cycle de vie complet de sécurisation d'une application SaaS moderne intégrant du RAG (Retrieval-Augmented Generation) :
1. **Phase 1 (Actuelle - v0)** : Construction de l'architecture multi-tenant avec failles délibérées documentées.
2. **Phase 2 (À venir)** : Pentest offensif (Burp Suite, `jwt_tool`, ffuf), rédaction du rapport d'audit et remédiation manuelle du code vers une version `v1` durcie.
3. **Phase 3 (À venir)** : Stack d'observabilité et de détection (Promtail, Loki, Grafana), mise en place de règles SIEM/alertes et simulation d'incident avec runbook.

---

## 🏗️ Architecture & Stack Technique

- **API Backend** : [FastAPI](https://fastapi.tiangolo.com/) (Python 3.11)
- **Base Relationnelle** : [PostgreSQL 15](https://www.postgresql.org/) via SQLAlchemy ORM
- **Base Vectorielle** : [ChromaDB](https://www.trychroma.com/) (stockage persistent des embeddings de documents)
- **Modèle LLM** : [Google Gemini](https://ai.google.dev/) (avec stub/mock intégré fonctionnant hors-ligne sans clé requise)
- **Conteneurisation** : [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)

---

## 🚀 Démarrage Rapide

Le projet démarre avec une seule commande standard :

```bash
docker compose up --build
```

Pour démarrer l'application avec la **stack d'observabilité complète** (Loki, Promtail, Grafana) :

```bash
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
```
Consultez le guide [OBSERVABILITY.md](file:///C:/Users/HP/Desktop/TenantGuard/OBSERVABILITY.md) pour les détails d'accès et requêtes LogQL.

L'API FastAPI est immédiatement disponible sur :
- **Documentation Swagger interactive** : [http://localhost:8000/docs](http://localhost:8000/docs)
- **Documentation ReDoc** : [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Vérification de santé (Healthcheck)** : [http://localhost:8000/health](http://localhost:8000/health)
- **Grafana (Observabilité & Audit)** : [http://127.0.0.1:3000](http://127.0.0.1:3000) (identifiants configurés via `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` dans `.env`, lié exclusivement à `127.0.0.1`)

---

## 🔑 Données Initiales et Comptes de Démonstration (Seed)

Au premier lancement, la base PostgreSQL et ChromaDB sont automatiquement initialisées avec **3 tenants** et **3 utilisateurs pré-configurés** :

| Tenant ID | Organisation | Identifiant (Username) | Mot de passe | Rôle | Document d'exemple indexé |
|---|---|---|---|---|---|
| **1** | Acme Corp | `alice` | `alice123` | `admin` | `acme_strategic_acquisition_2026.txt` |
| **2** | CyberDyne Systems | `bob` | `bob123` | `admin` | `cyberdyne_skynet_defense_specs.txt` |
| **3** | Initech | `charlie` | `charlie123` | `user` | `initech_payroll_master.txt` |

*(Vous pouvez également créer de nouveaux tenants ou inscrire des utilisateurs via les routes d'API).*

---

## ⚙️ Configuration & Sécurisation (.env)

Avant de lancer l'application, configurez les variables d'environnement en copiant le fichier exemple :

```bash
cp .env.example .env
```

### Procédure de génération des secrets obligatoires

L'application refuse strictement de démarrer si `JWT_SECRET` est absent ou comporte moins de 32 caractères (256 bits d'entropie). 

1. **Génération d'un secret JWT cryptographiquement fort (minimum 32 caractères) :**
   ```bash
   # Sous Linux / macOS / WSL / Git Bash :
   openssl rand -hex 32

   # Sous PowerShell :
   [Convert]::ToHexString((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))

   # Ou via Python :
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Génération d'un mot de passe fort pour PostgreSQL :**
   ```bash
   openssl rand -base64 24
   ```

3. **Génération d'un mot de passe fort pour Grafana (Observabilité) :**
   ```bash
   openssl rand -base64 24
   ```

Reportez ensuite les valeurs générées dans votre fichier `.env` :

```env
POSTGRES_USER=tenantguard
POSTGRES_PASSWORD=<VOTRE_MOT_DE_PASSE_POSTGRES_GENERE>
POSTGRES_DB=tenantguard_db
DATABASE_URL=postgresql://tenantguard:<VOTRE_MOT_DE_PASSE_POSTGRES_GENERE>@db:5432/tenantguard_db

JWT_SECRET=<VOTRE_SECRET_JWT_GENERE_MIN_32_CHARS>
JWT_ALGORITHM=HS256
UPLOAD_DIR=/app/uploads
CHROMA_PERSIST_DIR=/app/chroma_data
GEMINI_API_KEY=               # Laissez vide pour utiliser le mock LLM intégré, ou renseignez votre clé Gemini
GEMINI_MODEL=gemini-1.5-flash

# Observabilité (Loki / Grafana) - ports liés à 127.0.0.1 (localhost uniquement)
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=<VOTRE_MOT_DE_PASSE_GRAFANA_GENERE>
```

---

## 📡 Présentation des Routes d'API (v0)

### 1. Authentification & Gestion des Tenants (`/auth`)
- `POST /auth/login` : Authentification et obtention d'un jeton JWT.
- `POST /auth/register` : Inscription d'un nouvel utilisateur dans un tenant.
- `GET /auth/me` : Consultation du profil utilisateur connecté.
- `GET /auth/tenants` : Liste des tenants déclarés.
- `POST /auth/tenants` : Création d'un nouveau tenant.

### 2. Gestion des Documents (`/documents`)
- `POST /documents/upload` : Téléversement multipart d'un document (indexé automatiquement dans ChromaDB).
- `GET /documents` : Liste des documents (supporte le paramètre optionnel `?tenant_id=`).
- `GET /documents/{id}` : Métadonnées d'un document spécifique.
- `GET /documents/{id}/download` : Téléchargement du fichier binaire.
- `DELETE /documents/{id}` : Suppression du document et de ses embeddings.

### 3. Recherche et RAG Multi-Tenant (`/rag`)
- `POST /rag/query` : Recherche sémantique dans ChromaDB et génération d'une réponse par LLM.
  ```json
  {
    "query": "Quels sont les détails du projet confidentiel ?",
    "tenant_id": 1,
    "top_k": 3
  }
  ```
- `GET /rag/stats` : Statistiques de la collection vectorielle ChromaDB.

---

## 🧪 Exécution des Tests

Les tests automatisés vérifient le démarrage de l'application, les routes principales ainsi que la présence effective des failles v0 :

```bash
# Exécution locale avec pytest
pytest -v
```

---

## 📁 Arborescence du Dépôt

```
tenantguard/
├── README.md                 # Documentation principale du projet
├── KNOWN_ISSUES_V0.md        # Catalogue officiel des vulnérabilités v0
├── docker-compose.yml        # Orchestration PostgreSQL + API FastAPI
├── Dockerfile                # Image conteneur Python 3.11
├── requirements.txt          # Dépendances Python
├── .env.example              # Variables d'environnement de référence
├── .gitignore                # Exclusion des fichiers temporaires et données
├── app/
│   ├── main.py               # Point d'entrée FastAPI & cycle de vie
│   ├── auth.py               # Gestion JWT (failles secret faible et verify_exp=False)
│   ├── models.py             # Modèles SQLAlchemy (Tenant, User, Document)
│   ├── database.py           # Connexion DB et fonction de seed automatique
│   ├── logging_config.py     # Configuration des logs d'audit structurés
│   ├── rag_service.py        # Service ChromaDB & intégration LLM (Gemini / Mock)
│   └── routes/
│       ├── auth.py           # Routes d'authentification et tenants
│       ├── documents.py      # Routes de gestion de documents (failles BOLA & upload)
│       └── rag.py            # Route de requête RAG (failles fuite & injection)
└── tests/
    ├── conftest.py           # Fixtures de test et environnement éphémère
    ├── test_auth.py          # Tests d'authentification et validation de la faille JWT
    ├── test_documents.py     # Tests de gestion documentaire et failles IDOR/upload
    └── test_rag.py           # Tests RAG et vérification de la fuite cross-tenant
```

---

## 🚨 Détection des Menaces & Alerting (Grafana Unified Alerting)

TenantGuard intègre un système de détection des menaces et d'alerting en temps réel, provisionné entièrement sous forme de code :
- **Règles d'alerte Grafana Unified Alerting** : 7 règles de sécurité provisionnées dans `config/grafana/provisioning/alerting/` couvrant les attaques par force brute, le credential stuffing, les violations d'accès cross-tenant (IDOR/BOLA), les abus d'upload, le vol/rejeu de tokens, la prise de contrôle de compte (ATO) et l'exfiltration massive de données.
- **Mapping MITRE ATT&CK** : Toutes les règles sont étiquetées avec leurs techniques MITRE ATT&CK (`T1110`, `T1110.004`, `T1078`, `T1190`, `T1105`, `T1528`, `T1530`) et leur sévérité.
- **Tableau de bord de détection** : Dashboard Grafana pré-provisionné **Detection Overview** (`tenantguard-detection-overview`) avec vue d'ensemble des alertes actives, séries temporelles par sévérité, top IP attaquantes, top utilisateurs en violation cross-tenant et flux de logs d'audit.
- **Récepteur d'alertes Webhook** : Micro-service local (`alert-receiver`) consignant les alertes HTTP POST au format JSON sur stdout.
- **Runbooks de Réponse à Incident** : Chaque alerte pointe directement vers son guide de triage et de confinement dans [`docs/runbooks/`](docs/runbooks/).
- **Simulation d'Attaques & Vérification** : Suite de simulation automatisée rejouant les vecteurs d'attaque et vérifiant le passage à l'état `Firing` de toutes les alertes. Aucun mot de passe par défaut n'est codé en dur dans les scripts ; les variables d'environnement sont obligatoires et leurs valeurs de démonstration correspondent au tableau des comptes de seed (`alice123`, `bob123`, `charlie123`) :
  ```bash
  ALICE_PASSWORD=alice123 BOB_PASSWORD=bob123 CHARLIE_PASSWORD=charlie123 \
  GRAFANA_ADMIN_PASSWORD=secretgrafanapass123 \
  bash scripts/verify_detections.sh
  ```
- **Simulation d'Incident Réaliste & Post-Mortem** : Scénario d'attaque complet de bout en bout en 4 phases chronologiques avec pauses réalistes pour Loki (`scripts/run_incident.sh`), investigation médico-légale et post-mortem blameless :
  - **Script de simulation d'incident** : [`scripts/run_incident.sh`](scripts/run_incident.sh)
  - **Rapport d'investigation médico-légale LogQL** : [`docs/incident/INVESTIGATION.md`](docs/incident/INVESTIGATION.md)
  - **Preuves réelles de confinement** : [`docs/incident/CONTAINMENT_EVIDENCE.md`](docs/incident/CONTAINMENT_EVIDENCE.md)
  - **Post-Mortem de sécurité blameless** : [`docs/incident/POSTMORTEM.md`](docs/incident/POSTMORTEM.md)

- **Note DAST (CI/CD)** : Dans le workflow GitHub Actions, le job DAST OWASP ZAP Baseline se termine avec le code de sortie `2` (warnings passifs sur les en-têtes HTTP) et est configuré comme informatif.

Pour la documentation complète des règles, des requêtes LogQL et des scénarios de réponse :  
👉 **Consultez [DETECTION.md](DETECTION.md)**.

---

## 🔐 Registre des Vulnérabilités (v0)

Pour le détail des failles, leur criticité, leur localisation exacte et les vecteurs d'attaque :  
👉 **Consultez [KNOWN_ISSUES_V0.md](KNOWN_ISSUES_V0.md)**.
