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

L'API FastAPI est immédiatement disponible sur :
- **Documentation Swagger interactive** : [http://localhost:8000/docs](http://localhost:8000/docs)
- **Documentation ReDoc** : [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Vérification de santé (Healthcheck)** : [http://localhost:8000/health](http://localhost:8000/health)

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

## ⚙️ Configuration (.env)

Copiez le modèle de configuration si vous souhaitez personnaliser les paramètres (comme brancher une vraie clé Google Gemini) :

```bash
cp .env.example .env
```

Variables disponibles :

```env
DATABASE_URL=postgresql://tenantguard:tenantguard_secret@db:5432/tenantguard_db
JWT_SECRET=secret123
JWT_ALGORITHM=HS256
UPLOAD_DIR=/app/uploads
CHROMA_PERSIST_DIR=/app/chroma_data
GEMINI_API_KEY=               # Laissez vide pour utiliser le mock LLM intégré, ou renseignez votre clé Gemini
GEMINI_MODEL=gemini-1.5-flash
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

## 🔐 Registre des Vulnérabilités (v0)

Pour le détail des failles, leur criticité, leur localisation exacte et les vecteurs d'attaque :  
👉 **Consultez [KNOWN_ISSUES_V0.md](file:///C:/Users/HP/Desktop/TenantGuard/KNOWN_ISSUES_V0.md)**.
