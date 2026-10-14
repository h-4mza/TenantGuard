# Observabilité & Surveillance Sécurité — TenantGuard 📊

Ce document décrit l'architecture d'observabilité de TenantGuard, basée sur **Loki**, **Promtail** et **Grafana**, pour la centralisation, l'indexation et la visualisation des flux d'audit de sécurité.

---

## 🏗️ Architecture d'Observabilité

```mermaid
flowchart LR
    A["API TenantGuard\n(tenantguard_api)"] -->|"Logs JSON\n(stdout)"| B["Promtail\n(docker_sd_configs)"]
    B -->|"Stage JSON\n(labels: event, level)"| C["Loki :3100\n(Stockage TSDB / Chunks)"]
    D["Grafana :3000\n(Dashboard Provisionné)"] -->|"Requêtes LogQL"| C
```

- **API TenantGuard (`tenantguard_api`)** : émet chaque événement d'audit de sécurité en JSON structuré sur une seule ligne sur `stdout` via le logger dédié `tenantguard.audit`.
- **Promtail (`tenantguard_promtail`)** : découvre dynamiquement le conteneur `tenantguard_api` via l'API Docker (`docker_sd_configs`), extrait et labellise les métadonnées (`event`, `level`), et pousse vers Loki.
- **Loki (`tenantguard_loki`)** : stocke et indexe les streams de logs sur le système de fichiers local (`/loki`).
- **Grafana (`tenantguard_grafana`)** : expose l'interface visuelle sur le port `3000`, avec provisionnement automatique de la source de données Loki et du tableau de bord d'audit sécurité.

---

## ⚡ Démarrage de la Stack

Les services d'observabilité sont isolés sous le profil Docker Compose `observability` afin de ne pas ralentir ni impacter l'environnement de développement standard et les pipelines CI/CD (DAST).

### 1. Démarrer toute la stack (App + Observabilité)

```bash
docker compose --profile observability up -d --build
```

### 2. Démarrer uniquement l'application et la base (Mode CI / DAST standard)

```bash
docker compose up -d
```

> [!NOTE]
> `docker compose up` (sans profil) démarre exclusivement `tenantguard_db` et `tenantguard_api`.

---

## 🖥️ Accès à Grafana & Tableau de Bord

| Service | URL | Identifiants par défaut |
| :--- | :--- | :--- |
| **Grafana** | [http://localhost:3000](http://localhost:3000) | Utilisateur : `admin`<br>Mot de passe : `admin` |
| **Loki** | [http://localhost:3100](http://localhost:3100) | Interne / proxyisé |

Le dashboard de départ est automatiquement provisionné dans le dossier **TenantGuard** :
- **Titre du Dashboard :** `TenantGuard - Audit & Observabilité Sécurité`
- **UID :** `tenantguard-security-overview`
- **Panels inclus :**
  1. **Volume des événements par type dans le temps** (Time series / diagramme en barres empilées)
  2. **Tentatives de Connexion Échouées (`AUTH_LOGIN_FAILED`)** (Tableau des logs récents avec utilisateur et IP)
  3. **Refus d'Accès Inter-Tenant (`DOCUMENT_ACCESS_DENIED`)** (Tableau de détection des tentatives IDOR)
  4. **Activité & Requêtes RAG (`RAG_QUERY`)** (Historique des requêtes RAG et chunks extraits)

---

## 🔍 Exemples de Requêtes LogQL

Dans l'onglet **Explore** de Grafana (ou au sein des panels), vous pouvez interroger les logs à l'aide de LogQL :

### 1. Filtrer les échecs d'authentification et extraire les champs JSON
```logql
{container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED"
```

### 2. Détecter les tentatives d'accès non autorisées (IDOR inter-tenant)
```logql
{container="tenantguard_api"} | json | event="DOCUMENT_ACCESS_DENIED"
```

### 3. Calculer le taux d'événements par type par minute (Graphique)
```logql
sum by (event) (count_over_time({container="tenantguard_api"} | json | event != "" [1m]))
```

### 4. Filtrer les requêtes RAG posées par un utilisateur ou tenant spécifique
```logql
{container="tenantguard_api"} | json | event="RAG_QUERY" | user_tenant=1
```

### 5. Rechercher toutes les alertes de sécurité (niveau WARNING)
```logql
{container="tenantguard_api", level="WARNING"} | json
```

---

## 🛑 Arrêt des Services

Pour arrêter l'ensemble des conteneurs :

```bash
docker compose --profile observability down
```
