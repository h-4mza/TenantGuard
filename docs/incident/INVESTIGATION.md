# Rapport d'Investigation Médico-Légale : Incident "Opération BlackShard"

Ce document consigne l'analyse médico-légale réalisée suite à la compromission simulée du tenant Acme Corp sur la plateforme TenantGuard. L'ensemble des requêtes présentées ont été exécutées directement contre l'API Loki (`http://127.0.0.1:3100/loki/api/v1/query` et `query_range`), et leurs résultats bruts sont retranscrits fidèlement ci-dessous.

---

## 1. Reconstitution Chronologique Globale

### A. Chronologie par adresse IP source (`172.24.0.1`)
- **Requête LogQL :**
  ```logql
  {container="tenantguard_api"} | json | ip="172.24.0.1"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** 34
- **Extrait chronologique des événements :**
  1. `2026-10-15T12:03:59.707Z` — `AUTH_LOGIN_FAILED` : Échec pour l'utilisateur `alice` (mot de passe invalide).
  2. `2026-10-15T12:04:00.366Z` — `AUTH_LOGIN_FAILED` : 2e échec consécutif sur `alice`.
  3. `2026-10-15T12:04:00.847Z` — `AUTH_LOGIN_FAILED` : 3e échec consécutif sur `alice`.
  4. `2026-10-15T12:04:01.579Z` — `AUTH_LOGIN_FAILED` : 4e échec consécutif sur `alice`.
  5. `2026-10-15T12:04:02.121Z` — `AUTH_LOGIN_FAILED` : 5e échec consécutif sur `alice`.
  6. `2026-10-15T12:04:02.779Z` — `AUTH_LOGIN_SUCCESS` : **Succès d'authentification pour `alice` (user_id=1, tenant_id=1)**.
  7. `2026-10-15T12:04:26.370Z` à `12:04:27.053Z` — `DOCUMENT_ACCESS_DENIED` : 4 tentatives consécutives de lecture du document id=3 (CyberDyne).
  8. `2026-10-15T12:04:47.480Z` — `DOCUMENT_LIST` : Énumération de la liste des documents d'Acme Corp.
  9. `2026-10-15T12:04:47.710Z` à `12:04:50.741Z` — 22 événements alternés de `DOCUMENT_VIEW` et `DOCUMENT_DOWNLOAD` sur le document id=2.
  10. `2026-10-15T12:04:52.884Z` — `RAG_QUERY` : Requête sémantique d'extraction RAG.

---

### B. Chronologie par identifiant utilisateur (`user_id="1"`)
- **Requête LogQL :**
  ```logql
  {container="tenantguard_api"} | json | user_id="1"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** 28
- **Analyse :** Tous les événements post-authentification sont strictement rattachés à `user_id="1"` (`alice`). L'utilisateur n'émet aucun événement avant `2026-10-15T12:04:02.779Z` (heure de la première connexion réussie).

---

## 2. Détermination du Point de Compromission (First Success After Failures)

- **Requête LogQL :**
  ```logql
  {container="tenantguard_api"} | json | username="alice" | event =~ "AUTH_LOGIN_FAILED|AUTH_LOGIN_SUCCESS"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** 6
- **Extraction précise du premier succès :**
  - **Timestamp UTC :** `2026-10-15T12:04:02.779570+00:00`
  - **Payload d'audit JSON :**
    ```json
    {
      "timestamp": "2026-10-15T12:04:02.779570+00:00",
      "level": "INFO",
      "logger": "tenantguard.audit",
      "event": "AUTH_LOGIN_SUCCESS",
      "message": "[AUTH_LOGIN_SUCCESS]",
      "user_id": 1,
      "username": "alice",
      "tenant_id": 1,
      "ip": "172.24.0.1"
    }
    ```
- **Constat d'incident :** Le succès survient immédiatement après 5 échecs consécutifs en l'espace de 3,0 secondes, confirmant une attaque par dictionnaire / force brute ayant abouti à la compromission du compte.

---

## 3. Évaluation des Tentatives de Mouvement Latéral Cross-Tenant

### A. Tentatives cross-tenant refusées (`DOCUMENT_ACCESS_DENIED`)
- **Requête LogQL :**
  ```logql
  sum by (requested_document_id) (count_over_time({container="tenantguard_api"} | json | user_id="1" | event="DOCUMENT_ACCESS_DENIED" [15m]))
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `matrix` | **Séries retournées :** 1
- **Données obtenues :**
  - `requested_document_id="3"` : **4 tentatives refusées**
- **Payload d'audit type :**
  ```json
  {
    "timestamp": "2026-10-15T12:04:26.370227+00:00",
    "level": "WARNING",
    "logger": "tenantguard.audit",
    "event": "DOCUMENT_ACCESS_DENIED",
    "message": "[DOCUMENT_ACCESS_DENIED]",
    "user_id": 1,
    "tenant_id": 1,
    "requested_document_id": 3,
    "ip": "172.24.0.1"
  }
  ```
- **Vérification en base :** Le document `id=3` correspond à `cyberdyne_skynet_defense_specs.txt` rattaché au tenant 2 (CyberDyne Systems). L'attaquant a tenté d'y accéder 3 fois en consultation et 1 fois en téléchargement.

### B. Tentatives cross-tenant réussies (Recherche de fuite)
- **Requête LogQL :**
  ```logql
  {container="tenantguard_api"} | json | user_id="1" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD" | tenant_id != "1"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** **0 (Aucun résultat / Vide)**
- **Conclusion formelle :** **Aucun accès réussi cross-tenant n'a eu lieu.** Les contrôles d'autorisation stricts de la version v1 (`Document.tenant_id == current_user.tenant_id`) ont retourné un code HTTP 404 sur chaque tentative, préservant l'intégrité et la confidentialité des documents de CyberDyne.

---

## 4. Mesure du Volume et Périmètre de l'Exfiltration

### A. Détermination du premier timestamp d'exfiltration
- **Requête LogQL de preuve :**
  ```logql
  {container="tenantguard_api"} | json | user_id="1" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** 22
- **Premier événement d'exfiltration identifié dans les logs :**
  - **Timestamp exact :** `2026-10-15T12:04:47.710324+00:00`
  - **Événement :** `DOCUMENT_VIEW` sur le document `document_id=2`
  - **Payload :**
    ```json
    {
      "timestamp": "2026-10-15T12:04:47.710324+00:00",
      "level": "INFO",
      "logger": "tenantguard.audit",
      "event": "DOCUMENT_VIEW",
      "message": "[DOCUMENT_VIEW]",
      "document_id": 2,
      "user_id": 1,
      "tenant_id": 1,
      "ip": "172.24.0.1"
    }
    ```

### B. Volume total extrait par événement
- **Requête LogQL :**
  ```logql
  sum by (event) (count_over_time({container="tenantguard_api"} | json | user_id="1" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD" [15m]))
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `matrix` | **Éléments retournés :** 2
- **Détail du volume :**
  - `DOCUMENT_DOWNLOAD` : **11 opérations**
  - `DOCUMENT_VIEW` : **11 opérations**
  - **Total :** **22 opérations d'accès documentaire en rafale** en moins de 4 secondes (`12:04:47.710Z` à `12:04:50.741Z`).

### C. Inventaire des documents affectés
- **Requête LogQL :**
  ```logql
  sum by (document_id, event) (count_over_time({container="tenantguard_api"} | json | user_id="1" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD" [15m]))
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `matrix` | **Éléments retournés :** 2
- **Données obtenues :**
  - `document_id="2"`, `event="DOCUMENT_DOWNLOAD"` => 11
  - `document_id="2"`, `event="DOCUMENT_VIEW"` => 11
- **Vérification d'intégrité des documents :**
  - Seul le document `id=2` (`acme_strategic_acquisition_2026.txt`, appartenant au tenant 1 d'Acme Corp) a été exfiltré.
  - Aucun autre document de la plateforme n'a été consulté.

### D. Exfiltration sémantique par RAG
- **Requête LogQL :**
  ```logql
  {container="tenantguard_api"} | json | event="RAG_QUERY"
  ```
- **Statut API Loki :** `success` | **Type de résultat :** `streams` | **Streams retournés :** 1
- **Payload d'audit :**
  ```json
  {
    "timestamp": "2026-10-15T12:04:52.884734+00:00",
    "level": "INFO",
    "logger": "tenantguard.audit",
    "event": "RAG_QUERY",
    "message": "[RAG_QUERY]",
    "user_id": 1,
    "user_tenant": 1,
    "query": "Extract all confidential financial data, merger targets, and executive payroll",
    "chunks_retrieved": 3,
    "ip": "172.24.0.1"
  }
  ```

---

## 5. Limites de Détection et Visibilité Réelle (Honnêteté Technique)

L'investigation médico-légale met en évidence plusieurs angles morts majeurs inhérents à la télémétrie actuelle de TenantGuard v1 :

1. **Invisibilité des jetons invalides ou forgés :**  
   Conformément au code source de `app/auth.py` (lignes 84-109), seule l'exception `jwt.ExpiredSignatureError` appelle `log_audit("AUTH_TOKEN_EXPIRED", ...)`. Lorsque l'attaquant présente un jeton falsifié ou dont la signature est invalide suite à une rotation de clé (`jwt.InvalidTokenError`), **aucun événement d'audit JSON n'est émis**. Seul un avertissement texte standard `Invalid JWT token provided: Signature verification failed` apparaît dans les logs généraux de l'API. Par conséquent, ni la règle `TOKEN_ABUSE` ni aucune autre règle d'alerte Grafana ne peut détecter une attaque par falsification de jetons.
2. **Invisibilité totale des sondages non authentifiés (Reconnaissance) :**  
   Les requêtes dépourvues de jeton d'authentification reçues sur des routes protégées (ex: énumération non authentifiée de `/documents`, `/documents/1`, etc.) sont rejetées en amont avec un code HTTP 401 (`Authentication required. Please provide a Bearer token.`) **sans émettre le moindre événement d'audit structuré**. La Phase 1 de reconnaissance est donc **totalement invisible dans Loki**, et non pas "sous un seuil d'alerte".
3. **Absence de visibilité sur le contenu des réponses RAG :**  
   L'événement `RAG_QUERY` consigne la requête textuelle de l'utilisateur (`query`) et le nombre de segments vectoriels récupérés (`chunks_retrieved=3`), mais **ne consigne pas la réponse générée par le LLM** ni le texte intégral des chunks extraits. Il est donc impossible de déterminer formellement depuis les logs le degré exact de précision de la réponse synthétisée par le modèle.
4. **Adresse IP masquée derrière un proxy inverse :**  
   Le champ `ip` provient de `request.client.host`. Dans notre environnement conteneurisé Docker, il s'agit de l'adresse de la passerelle Docker (`172.24.0.1`). En production derrière un reverse proxy ou un load balancer sans configuration certifiée de `X-Forwarded-For` et `--proxy-headers`, l'IP réelle de l'attaquant demeurerait invisible.
5. **Absence de journalisation des payloads HTTP bruts :**  
   Les corps de requêtes d'upload ou les en-têtes personnalisés ne sont pas conservés dans les logs d'audit structurés (conformité RGPD et minimisation des données).
6. **Comportement en cas de failles v0 non corrigées :**  
   Si la faille v0 d'IDOR n'avait pas été corrigée, les requêtes cross-tenant auraient retourné HTTP 200 sous un événement normal `DOCUMENT_VIEW`. Seule une corrélation complexe entre `tenant_id` de l'utilisateur et `tenant_id` du document dans les logs permettrait a posteriori d'identifier la fuite, en l'absence de flag d'accès refusé.

