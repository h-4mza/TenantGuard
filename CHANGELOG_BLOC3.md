# TenantGuard — Changelog Bloc 3 : Remédiation des Vulnérabilités

Ce document consigne l'ensemble des corrections techniques implémentées dans le cadre du **Bloc 3** de TenantGuard. Ces remédiations corrigent les 8 vulnérabilités identifiées et documentées lors du pentest, tout en préservant l'intégrité opérationnelle de la plateforme SaaS multi-tenant.

---

## 1. Vue d'ensemble des commits

| Commit | Scope | Description technique | Fichiers touchés |
|---|---|---|---|
| `1c0c966` | **FINDING-01 & FINDING-08** | Clé JWT faible & secrets codés en dur dans la configuration | `app/auth.py`, `docker-compose.yml`, `.env.example`, `README.md`, `tests/conftest.py`, `tests/test_auth.py` |
| `3a82fc1` | **FINDING-02** | Absence de vérification de l'expiration du jeton JWT | `app/auth.py`, `tests/test_auth.py` |
| `06cea57` | **FINDING-03 & FINDING-04** | BOLA / IDOR sur les routes de gestion des documents | `app/routes/documents.py`, `tests/test_documents.py` |
| `612d144` | **FINDING-05** | Traversée de répertoire (Path Traversal) à l'upload | `app/routes/documents.py`, `tests/test_documents.py` |
| `8411c4d` | **FINDING-06** | Fuite de données cross-tenant dans la recherche vectorielle RAG | `app/rag_service.py`, `app/routes/rag.py`, `tests/test_rag.py` |
| `a902129` | **FINDING-07** | Atténuation de l'injection de prompt (Prompt Injection) | `app/rag_service.py`, `tests/test_rag.py` |

---

## 2. Détail des remédiations techniques

### FINDING-01 & FINDING-08 : Clé JWT faible et secrets en dur dans les configurations
* **Vulnérabilité :** `JWT_SECRET` utilisait une valeur par défaut de secours triviale (`secret123`), facilitant les attaques par force brute hors-ligne. De plus, `JWT_SECRET=secret123` et `POSTGRES_PASSWORD=tenantguard_secret` étaient codés en dur dans `docker-compose.yml` et exposés dans `.env.example`.
* **Modifications techniques :**
  - **`app/auth.py`** : Suppression de tout fallback par défaut. Au démarrage de l'application, validation stricte de `os.getenv("JWT_SECRET")` ; si le secret est absent, inférieur à 32 caractères (256 bits), ou correspond à une chaîne de remplacement prédéfinie (`CHANGE_ME_*`), une exception fatale `RuntimeError` est levée, empêchant le serveur de démarrer dans un état non sécurisé.
  - **`docker-compose.yml`** : Retrait complet des valeurs de repli par défaut (`JWT_SECRET=${JWT_SECRET}` et `POSTGRES_PASSWORD=${POSTGRES_PASSWORD}`) afin d'interdire tout démarrage silencieux avec un secret par défaut si les variables ne sont pas explicitement définies dans l'environnement.
  - **`.env.example`** : Placeholders explicites (`CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32`).
  - **`README.md`** : Ajout de la documentation des commandes de génération cryptographique (`openssl rand -hex 32`).
* **Justification :** Le principe de *Secure by Default* impose le refus de démarrage (*fail-fast*) dès lors qu'un secret cryptographique maître est absent ou vulnérable au craquage par dictionnaires.

---

### FINDING-02 : Absence de vérification de l'expiration des jetons JWT
* **Vulnérabilité :** `jwt.decode()` dans `app/auth.py` incluait `options={"verify_exp": False}`, autorisant l'usage indéfini de jetons révoqués ou périmés.
* **Modifications techniques :**
  - **`app/auth.py`** : Suppression de `options={"verify_exp": False}` pour rétablir la vérification native de PyJWT sur le claim `exp`.
  - Capture explicite de l'exception `jwt.ExpiredSignatureError` retournant un code `401 Unauthorized` avec le message d'erreur `"Token expired"` et l'en-tête `WWW-Authenticate: Bearer`.
* **Justification :** L'expiration stricte limite la fenêtre temporelle d'exploitation en cas de vol d'identifiant ou d'interception d'un jeton d'accès.

---

### FINDING-03 & FINDING-04 : Vulnérabilités BOLA / IDOR sur les documents
* **Vulnérabilité :** 
  - À l'upload (`POST /documents/upload`), le paramètre `tenant_id` envoyé par le client était utilisé pour assigner le document, permettant l'injection de documents dans d'autres organisations.
  - Au listage (`GET /documents`), l'omission du paramètre renvoyait l'ensemble des documents de la base (fuite globale), et un client pouvait filtrer arbitrairement sur n'importe quel `tenant_id`.
  - À la consultation, téléchargement ou suppression (`GET /documents/{id}`, `GET /documents/{id}/download`, `DELETE /documents/{id}`), aucun contrôle d'appartenance au tenant de l'utilisateur n'était opéré.
* **Modifications techniques :**
  - **`app/routes/documents.py`** :
    - Retrait du paramètre client `tenant_id` sur toutes les routes.
    - L'upload force l'assignation du document au tenant de l'utilisateur authentifié : `target_tenant_id = current_user.tenant_id`.
    - La route de listage filtre strictement et exclusivement sur `Document.tenant_id == current_user.tenant_id`.
    - Les routes d'accès unitaire (`{id}`, `{id}/download`, `{id}`) appliquent la double clause SQL : `filter(Document.id == document_id, Document.tenant_id == current_user.tenant_id)`.
    - En cas de ressource inexistante ou appartenant à un autre tenant, l'API répond systématiquement par un statut `404 Not Found` (et non `403 Forbidden`).
* **Justification :** L'utilisation d'un code `404` plutôt que `403` supprime tout oracle permettant à un attaquant d'énumérer les identifiants de documents appartenant aux tenants concurrents.

---

### FINDING-05 : Traversée de répertoire (Path Traversal) et contrôle d'upload
* **Vulnérabilité :** L'upload utilisait directement `file.filename` non assaini avec `os.path.join`, permettant l'écriture arbitraire en dehors du répertoire désigné via des séquences `../`. Aucune restriction sur l'extension ou le volume du fichier n'était en place.
* **Modifications techniques :**
  - **`app/routes/documents.py`** :
    - Assainissement strict du nom de fichier avec `os.path.basename` et substitution par regex des caractères non alphanumériques (`re.sub(r"[^a-zA-Z0-9_.-]", "_", safe_name)`).
    - Génération d'un nom de stockage unique préfixé par un UUID v4 (`f"{uuid.uuid4()}_{safe_name}"`), éliminant tout risque d'écrasement ou d'accès prédictible.
    - Validation stricte par liste blanche d'extensions autorisées : `.txt`, `.pdf`, `.docx`, `.md`. Tout format non autorisé déclenche un statut `400 Bad Request`.
    - Contrôle du volume maximal fixé à 10 Mo (`MAX_FILE_SIZE = 10 * 1024 * 1024`), avec rejet via `413 Payload Too Large`.
* **Justification :** Neutralise les risques de Remote Code Execution (RCE), de déni de service (DoS par épuisement disque) et d'écrasement de fichiers critiques du conteneur.

---

### FINDING-06 : Fuite cross-tenant dans la recherche vectorielle RAG
* **Vulnérabilité :** La route `POST /rag/query` acceptait un paramètre client `tenant_id` sans le valider contre `current_user.tenant_id`. De plus, `rag_service.retrieve` autorisait les requêtes sans filtre (`tenant_id=None`), retournant des segments vectoriels appartenant à tous les clients.
* **Modifications techniques :**
  - **`app/routes/rag.py`** : Suppression du champ `tenant_id` du modèle Pydantic `RAGQueryRequest`. La route injecte obligatoirement `current_user.tenant_id` côté serveur lors de l'appel au service.
  - **`app/rag_service.py`** : Rendu du paramètre `tenant_id: int` strictement obligatoire dans `retrieve(query, tenant_id)`. Vérification de validité (`isinstance(tenant_id, int) and tenant_id > 0`) et application systématique du filtre `where={"tenant_id": tenant_id}` dans ChromaDB.
* **Justification :** Garantit l'étanchéité cryptographique et logique des espaces vectoriels dans la base ChromaDB, même en cas de tentative de manipulation des requêtes par un client.

---

### FINDING-07 : Atténuation de l'injection de prompt (Prompt Injection)
* **Vulnérabilité :** Le contenu des fragments vectoriels et la requête utilisateur étaient directement concaténés dans le gabarit textuel du prompt LLM sans délimitation structurelle, permettant aux utilisateurs d'écraser les consignes système par des instructions malveillantes (*jailbreaks*, *roleplay*, *system overrides*).
* **Modifications techniques :**
  - **`app/rag_service.py`** :
    - Définition d'une directive système `SYSTEM_INSTRUCTION` dédiée.
    - Transmission des consignes système au modèle Gemini via le paramètre natif `system_instruction` de l'API `GenerativeModel`, séparant le canal d'instruction du canal de données.
    - Structuration du prompt utilisateur via des balises de délimitation XML strictes (`<context><document index="..." source="..." tenant="...">...</document></context>` et `<user_query>...</user_query>`).
    - Consignes défensives explicites ordonnant au modèle de refuser et d'ignorer toute instruction trouvée dans les documents ou la requête utilisateur qui tenterait de modifier les règles système.

---

## 3. Analyse approfondie : Pourquoi l'injection de prompt est une atténuation et non un fix définitif

L'injection de prompt (qu'elle soit directe via la requête utilisateur ou indirecte via des documents indexés dans la base vectorielle) constitue un défi fondamental de sécurité propre à l'architecture actuelle des modèles de langage (LLMs) :

1. **Absence de séparation intrinsèque entre code et données :**
   Contrairement aux architectures informatiques traditionnelles où les architectures Harvard ou le bit NX séparent physiquement les instructions machine des données, les LLMs traitent l'ensemble de leur entrée (consignes développeur, documents externes et requêtes utilisateur) au sein d'un flux textuel unique sous forme de tokens d'attention. Pour le réseau de neurones, une consigne malveillante logée dans un document indexé est sémantiquement indiscernable d'une consigne système légitime.

2. **Nature probabiliste des modèles :**
   Les modèles de langage ne reposent pas sur une machine à états déterministe. Dès lors qu'un adversaire conçoit une invite suffisamment sophistiquée (techniques d'obfuscation, encodage Base64, substitution linguistique, attaques multi-étapes ou attaques par force brute d'optimisation de gradient), il subsiste une probabilité non nulle que le modèle privilégie la consigne adverse au détriment des consignes système.

3. **La stratégie adoptée : Défense en profondeur (*Defense-in-Depth*) :**
   En l'absence de solution mathématique absolue reconnue par la recherche en sécurité IA, les mesures implémentées dans TenantGuard constituent la meilleure pratique industrielle d'atténuation :
   - **Isolation vectorielle en amont (FINDING-06) :** C'est le rempart le plus critique. Même si un prompt injection parvenait à manipuler le modèle, la requête ChromaDB filtrant strictement sur `current_user.tenant_id`, **aucun vecteur étranger ne peut être chargé en mémoire**. L'impact maximal d'une injection réussie est restreint aux données du tenant de l'attaquant lui-même.
   - **Séparation structurelle des rôles :** Utilisation de l'API native `system_instruction` de Google Gemini pour placer les règles au niveau du métadrapeau système du modèle.
   - **Délimiteurs XML explicites :** Permettent au modèle d'identifier les frontières formelles entre le texte de référence et l'invite utilisateur.
   - **Garde-fous négatifs :** Règles explicites de rejet interdisant l'exécution de méta-commandes.

---

## 4. Vérification et validation des tests

La suite de tests unitaires et d'intégration a été entièrement actualisée pour vérifier le comportement sécurisé :
- `tests/test_auth.py` : 8/8 tests validés (rejet de secret manquant, rejet de placeholders/fallbacks, rejet des clés faibles `< 32` car., rejet `401` sur jetons expirés).
- `tests/test_documents.py` : 7/7 tests validés (isolation multi-tenant, `404` sur tentative cross-tenant, rejet des extensions interdites `400`, rejet des fichiers `> 10 Mo` avec `413`, assainissement contre la traversée de répertoire).
- `tests/test_rag.py` : 6/6 tests validés (isolation vectorielle absolue par tenant, validation des filtres `where`, résilience aux injections).

**Total : 21/21 tests automatisés au vert sous conteneur Docker.**
