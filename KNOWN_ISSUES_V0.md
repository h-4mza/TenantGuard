# Registre des Vulnérabilités & Matrice de Remédiation (v0 → v1.0) — TenantGuard

> [!NOTE]
> **Statut global du projet :**  
> Toutes les vulnérabilités v0 listées ci-dessous ont été **intégralement corrigées et auditées en v1.0**.  
> Ce document sert de registre de traçabilité entre les constatations du pentest initial ([`pentest/report.md`](file:///pentest/report.md)), les commits de remédiation, les tests automatisés de non-régression et les règles de détection associées.

---

## 1. Matrice de Remédiation des Vulnérabilités (v0 → v1.0)

| ID Finding | Catégorie (OWASP Top 10) | Description de la vulnérabilité v0 | Statut v1.0 | Commit de remédiation | Test automatisé de validation | Règle de détection Grafana / MITRE ATT&CK |
|---|---|---|---|---|---|---|
| **FINDING-01** | A07:2021 – Auth Failures | Clé de signature JWT faible par défaut (`secret123`) cassable hors-ligne | **Corrigée** | [`83b40d5`](file:///git/83b40d5), [`049b596`](file:///git/049b596) | `tests/test_auth.py::test_jwt_secret_enforced`, `test_login_success` | `BRUTE_FORCE_LOGIN` (`T1110`), `ACCOUNT_TAKEOVER_SUSPECT` (`T1078`) |
| **FINDING-02** | A07:2021 – Auth Failures | Absence de vérification d'expiration JWT (`verify_exp=False`) | **Corrigée** | [`2c19c18`](file:///git/2c19c18) | `tests/test_auth.py::test_expired_jwt_rejected`, `test_token_without_exp_rejected` | `TOKEN_ABUSE_SUSPECT` (`T1528`) |
| **FINDING-03** | A01:2021 – Broken Object Level Auth (BOLA / IDOR) | Consultation et téléchargement de documents cross-tenant sans vérification | **Corrigée** | [`fc1994c`](file:///git/fc1994c) | `tests/test_documents.py::test_list_documents_tenant_isolation`, `test_get_document_cross_tenant_forbidden_404`, `test_download_cross_tenant_forbidden_404` | `CROSS_TENANT_ACCESS` (`T1078`) |
| **FINDING-04** | A01:2021 – BOLA / IDOR | Assignation arbitraire de document à un autre tenant lors de l'upload | **Corrigée** | [`fc1994c`](file:///git/fc1994c) | `tests/test_documents.py::test_upload_document_isolated_to_own_tenant` | `UPLOAD_ANOMALY` (`T1105`) |
| **FINDING-05** | A04:2021 – Insecure Design | Upload sans restriction d'extension/taille et Path Traversal dans le nom | **Corrigée** | [`9bd76a7`](file:///git/9bd76a7) | `tests/test_documents.py::test_path_traversal_filename_sanitized`, `test_invalid_extension_rejected`, `test_oversize_file_upload_rejected` | `UPLOAD_ANOMALY` (`T1105` / `T1190`) |
| **FINDING-06** | OWASP LLM02 – Sensitive Info Disclosure | Requête RAG vectorielle sans filtre de cloisonnement tenant | **Corrigée** | [`bc007c0`](file:///git/bc007c0) | `tests/test_rag.py::test_rag_strict_tenant_isolation`, `test_rag_query_own_tenant` | `CROSS_TENANT_ACCESS` (`T1078`), `EXFILTRATION_VOLUME` (`T1530`) |
| **FINDING-07** | OWASP LLM01 – Prompt Injection | Fuite de données contextuelles par injection de prompt dans le LLM | **Corrigée** | [`780634d`](file:///git/780634d) | `tests/test_rag.py::test_rag_prompt_injection_guardrail_present`, `test_rag_delimiter_protection` | `EXFILTRATION_VOLUME` (`T1530`) |
| **FINDING-08** | A08:2021 – Security Misconfiguration | Secrets d'infrastructure en clair dans le dépôt et l'historique Git | **Corrigée** | [`83b40d5`](file:///git/83b40d5), [`049b596`](file:///git/049b596), [`a52ef1b`](file:///git/a52ef1b) | CI Job `Secrets (Gitleaks)`, documentation [`docs/HISTORY_PURGE.md`](file:///docs/HISTORY_PURGE.md) | N/A (Prévention CI/CD + Purge historique préparée) |

---

## 2. Détail des Vulnérabilités v0 et Preuves de Remédiation

### FINDING-01 & FINDING-08 : Secrets JWT et Infrastructure
- **Vulnérabilité v0 :** La clé secrète JWT par défaut était `"secret123"` et le mot de passe Postgres était codé en dur dans `docker-compose.yml` (`tenantguard_secret`).
- **Remédiation v1 :**
  - Validation stricte au démarrage : l'API lève une `RuntimeError` bloquante si `JWT_SECRET` est absent ou fait moins de 32 caractères.
  - Suppression de toutes les valeurs par défaut sensibles dans le code et les fichiers Compose.
  - Gate CI Gitleaks activé pour bloquer tout commit contenant un secret.
- **Vérification :** Pentest re-vérification [`91d1daf`](file:///git/91d1daf), tests unitaires `test_jwt_secret_enforced`.

### FINDING-02 : Ignorance de l'Expiration des Jetons JWT
- **Vulnérabilité v0 :** La fonction `decode_access_token` utilisait `options={"verify_exp": False}`.
- **Remédiation v1 :**
  - Activation de la vérification stricte `verify_exp: True`.
  - Rejet immédiat avec code HTTP `401 Unauthorized` et émission d'un événement d'audit `AUTH_LOGIN_FAILED` avec motif `"token_expired"`.
- **Vérification :** Pentest re-vérification [`f2ea4e5`](file:///git/f2ea4e5), tests unitaires `test_expired_jwt_rejected`.

### FINDING-03 & FINDING-04 : Contrôle d'Accès Cross-Tenant (IDOR / BOLA)
- **Vulnérabilité v0 :** Les endpoints `/documents` acceptaient un paramètre `tenant_id` non vérifié ou renvoyaient tous les documents si omis. Les opérations de lecture/téléchargement/suppression par `id` ne vérifiaient pas le propriétaire.
- **Remédiation v1 :**
  - Le `tenant_id` est obligatoirement dérivé du jeton JWT authentifié (`current_user.tenant_id`).
  - Toute tentative d'accès à un document d'un autre tenant lève un code HTTP `404 Not Found` (évite l'énumération par oracle d'erreur 403) et émet un log d'audit de sécurité `DOCUMENT_ACCESS_DENIED`.
- **Vérification :** Pentest re-vérification [`fb41fec`](file:///git/fb41fec), tests unitaires `test_get_document_cross_tenant_forbidden_404`.

### FINDING-05 : Upload Arbitraire & Path Traversal
- **Vulnérabilité v0 :** Upload sans validation de type MIME, sans limite de taille, et nom de fichier stocké via concaténation directe `UPLOAD_DIR + file.filename`.
- **Remédiation v1 :**
  - Assainissement du nom via `os.path.basename()` et stockage sous UUID aléatoire sur disque.
  - Liste blanche stricte des extensions (`.txt`, `.pdf`, `.docx`, `.csv`).
  - Limite stricte de taille à 10 Mo avec vérification du flux.
- **Vérification :** Pentest re-vérification [`701b483`](file:///git/701b483), tests `test_path_traversal_filename_sanitized`.

### FINDING-06 & FINDING-07 : Cloisonnement RAG & Guardrails Prompt Injection
- **Vulnérabilité v0 :** L'interrogation ChromaDB pouvait omettre le filtre `where={"tenant_id": ...}`, fusionnant les index de tous les clients. Le prompt utilisateur était injecté tel quel dans le prompt LLM sans délimiteur.
- **Remédiation v1 :**
  - Filtre `where={"tenant_id": current_user.tenant_id}` obligatoire et non surchargeable.
  - Délimiteurs stricts XML/Markdown (`<context>`, `<question>`) et instructions système fermées interdisant d'ignorer les règles de sécurité.
- **Vérification :** Pentest re-vérifications [`65d7328`](file:///git/65d7328) et [`34ea2dd`](file:///git/34ea2dd), tests `test_rag_strict_tenant_isolation`.

---

## 3. Limites Connues de la Version v1.0 (Angles Morts & Améliorations Futures)

Bien que la version v1.0 résolve toutes les vulnérabilités de la v0, l'évaluation opérationnelle (notamment lors de l'investigation d'incident du Bloc 6) a mis en évidence plusieurs limites architecturales assumées pour cette étape :

### 1. Angles morts de détection dans l'audit applicatif
- **Jetons invalides ou falsifiés (`AUTH_TOKEN_INVALID` non émis) :**
  Dans `app/auth.py`, seul le cas `ExpiredSignatureError` appelle `log_audit()`. Un jeton dont la signature cryptographique est invalide (clé modifiée, HMAC corrompu) lève une `PyJWTError` générique capturée au niveau HTTP (`HTTPException(401, "Invalid JWT token")`), ce qui n'émet aucun événement JSON structuré. Les tentatives de forge de jeton ne sont donc pas visibles dans Loki ni corrélées par les règles d'alerte.
- **Tentatives d'accès non authentifié (`AUTH_UNAUTHENTICATED_ACCESS` non émis) :**
  Les requêtes HTTP ciblant des routes protégées sans en-tête `Authorization` sont rejetées nativement par les dépendances FastAPI (`HTTPBearer`) avec un code 403/401 sans passer par le code applicatif, n'émettant aucun log d'audit JSON.

### 2. Absence de mécanisme de révocation unitaire de jeton (Blocklist)
- Les jetons JWT émis sont stateless et demeurent valides jusqu'à leur date d'expiration (`exp`), même si le compte utilisateur est ultérieurement verrouillé en base de données (`is_active = FALSE`).
- La seule mesure de confinement immédiate en cas de compromission d'un jeton actif est la **rotation globale de `JWT_SECRET`**, qui invalide indistinctement les sessions de l'ensemble des utilisateurs légitimes. L'implémentation d'une liste noire de révocation (Redis / cache distribué) constitue une action corrective post-mortem prioritaire.

### 3. Extraction de l'adresse IP client sans gestion des proxys inverses
- L'adresse IP consignée dans les logs d'audit est extraite directement de `request.client.host`.
- En environnement de production derrière un reverse proxy, un ingress Kubernetes ou un load-balancer (ALB/Cloudflare), cette valeur refléterait l'IP interne du proxy à moins d'activer le middleware `ProxyHeadersMiddleware` d'Uvicorn et d'inspecter `X-Forwarded-For` de façon sécurisée (avec restriction des proxys de confiance).

### 4. Montage du socket Docker (`/var/run/docker.sock`) dans Promtail
- Pour collecter automatiquement les logs stdout des conteneurs via le driver Docker, le service `promtail` bind-mounte le socket hôte `/var/run/docker.sock`.
- Bien que confiné au réseau interne d'observabilité, ce montage confère des privilèges équivalents à root sur la machine hôte si le conteneur Promtail venait à être compromis. En production Kubernetes, cette architecture devrait être remplacée par un DaemonSet collectant directement `/var/log/pods` sans accès au runtime socket.
