# Plan de purge de l'historique Git & Inventaire des secrets (FINDING-08)

> [!WARNING]
> **RÈGLE CRITIQUE D'INTÉGRITÉ ET DE SÉCURITÉ :**
> La réécriture de l'historique Git (`git-filter-repo`) modifie les identifiants SHA-1 de tous les commits descendants.
> **Aucun `git push --force` ne doit être exécuté sans validation explicite préalable de l'utilisateur.**
> La procédure a été préparée et validée de bout en bout sur une copie locale de test (`0 leak` Gitleaks, suite `pytest` 25/25 passante, `git diff` applicatif vide).

---

## 1. Contexte & Audit FINDING-08

L'audit de sécurité initial de TenantGuard v0 (documenté dans [`pentest/findings/FINDING-08-hardcoded-secrets-config.md`](file:///pentest/findings/FINDING-08-hardcoded-secrets-config.md) et [`pentest/report.md`](file:///pentest/report.md)) a relevé que plusieurs secrets et identifiants d'infrastructure étaient codés en dur dans les fichiers versionnés et dans l'historique des commits du dépôt (`docker-compose.yml`, `.env.example`, `app/auth.py`, `app/main.py`).

Bien que la version active (v1) ait assaini l'arbre de travail (`--no-git` propre dans la CI DevSecOps) en imposant l'injection par variables d'environnement cryptographiquement fortes, l'historique Git conserve les traces des versions antérieures et des preuves de pentest.

---

## 2. Inventaire exhaustif des secrets détectés dans l'historique

L'analyse de l'historique Git complet (52 commits scannés) au moyen de `gitleaks detect --source=. --verbose` a identifié **22 occurrences** de secrets réparties sur 10 valeurs uniques.

Conformément aux exigences de sécurité, **aucun secret n'est reproduit en clair ci-dessous** ; seules des empreintes masquées ou des descriptions de structure sont fournies.

| # | Commit (abrév.) | Fichier | Règle Gitleaks | Ligne | Valeur masquée / Empreinte | Classification & Justification |
|---|-----------------|---------|----------------|-------|----------------------------|--------------------------------|
| 1 | `0f1ed0f` | `scripts/simulate_attacks.sh` | `jwt` | 117 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...xCs` | **Secret de démonstration documenté** (ancien JWT expiré codé en dur pour test d'intrusion avant Bloc 5) |
| 2 | `aedda6e` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 35 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...k8I` | **Secret de pentest documenté** (jeton forgé avec la clé faible v0 comme preuve de concept) |
| 3 | `5980809` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 15 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...6kI` | **Secret de pentest documenté** (jeton de test de forge) |
| 4 | `ae7e15e` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 42 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton de session Alice v0) |
| 5 | `ae7e15e` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 104 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...eQ` | **Secret de pentest documenté** (jeton forgé pour élévation de privilège) |
| 6 | `ae7e15e` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 114 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...eQ` | **Secret de pentest documenté** (en-tête `Authorization: Bearer` forgé) |
| 7 | `ae7e15e` | `pentest/findings/FINDING-02-jwt-no-expiration.md` | `jwt` | 20 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton sans claim `exp`) |
| 8 | `ae7e15e` | `pentest/findings/FINDING-02-jwt-no-expiration.md` | `jwt` | 43 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (rejeu de jeton sans expiration) |
| 9 | `ae7e15e` | `pentest/findings/FINDING-03-cross-tenant-idor-documents.md` | `jwt` | 21 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton utilisateur tenant 1) |
| 10 | `ae7e15e` | `pentest/findings/FINDING-03-cross-tenant-idor-documents.md` | `jwt` | 31 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton pour IDOR) |
| 11 | `ae7e15e` | `pentest/findings/FINDING-03-cross-tenant-idor-documents.md` | `jwt` | 65 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton pour IDOR) |
| 12 | `ae7e15e` | `pentest/findings/FINDING-04-cross-tenant-assignment-upload.md` | `jwt` | 21 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton test upload cross-tenant) |
| 13 | `ae7e15e` | `pentest/findings/FINDING-05-insecure-upload-path-traversal.md` | `jwt` | 21 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton test path traversal) |
| 14 | `ae7e15e` | `pentest/findings/FINDING-06-rag-cross-tenant-leakage.md` | `generic-api-key` | 104 | `TOPSECRET...[REDACTED]...2026` | **Donnée de démonstration / PoC** (code d'accès fictif extrait d'un document confidentiel du tenant MegaCorp) |
| 15 | `ae7e15e` | `pentest/findings/FINDING-06-rag-cross-tenant-leakage.md` | `jwt` | 26 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton test fuite RAG) |
| 16 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `generic-api-key` | 52 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / PoC** (code trésorerie interne de la seed v0) |
| 17 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `generic-api-key` | 55 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / PoC** (code trésorerie interne de la seed v0) |
| 18 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `jwt` | 22 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton test prompt injection) |
| 19 | `ae7e15e` | `pentest/report.md` | `jwt` | 90 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 20 | `ae7e15e` | `pentest/report.md` | `jwt` | 94 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...eQ` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 21 | `ae7e15e` | `pentest/report.md` | `jwt` | 103 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 22 | `d063fd3` | `app/main.py` | `generic-api-key` | 32 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / Faux positif** (texte seed v0 inséré dans la base pour simuler un document confidentiel) |

### Autres secrets d'infrastructure initiaux (FINDING-08)
- `docker-compose.yml` (commit `d063fd3`) : `tenantguard_secret` (mot de passe Postgres v0) et `secret123` (clé secrète JWT v0).
- `.env.example` (commit `d063fd3`) : `secret123` et `tenantguard_secret`.
- `app/auth.py` (commit `d063fd3`) : valeur de repli `"secret123"`.

---

## 3. Procédure de purge recommandée (`git-filter-repo`)

La méthode standard et hautement recommandée par les mainteneurs de Git est l'utilisation de `git-filter-repo` (bien supérieure à `git filter-branch` et `BFG Repo-Cleaner` en termes de rapidité, de préservation des métadonnées et de propreté).

### Étape 1 : Sauvegarde locale de sécurité
Avant toute manipulation, poser un tag local immuable sur le commit actuel :
```bash
git tag backup-pre-purge
```

### Étape 2 : Préparation du clone miroir temporaire
Pour éviter d'endommager l'arbre de travail local :
```bash
cd /tmp # ou répertoire temporaire sous Windows
git clone --mirror https://github.com/h-4mza/TenantGuard.git tenantguard-mirror.git
cd tenantguard-mirror.git
```

### Étape 3 : Fichier de substitution (`expressions.txt`)
Créer un fichier `expressions.txt` listant les chaînes littérales exactes à remplacer par un marqueur inoffensif :
```text
tenantguard_secret==>[REDACTED_POSTGRES_PASSWORD]
secret123==>[REDACTED_DEV_JWT_SECRET]
ACMESECRET2026==>[REDACTED_SEED_DATA]
TOPSECRET2026==>[REDACTED_SEED_DATA]
<CHAINE_JWT_ALICE>==>[REDACTED_DEMO_JWT]
<CHAINE_JWT_FORGED>==>[REDACTED_DEMO_JWT]
...
```

### Étape 4 : Exécution de `git-filter-repo`
```bash
python -m git_filter_repo --replace-text expressions.txt --force
```

### Étape 5 : Vérification locale post-purge
1. **Contrôle Gitleaks sur l'historique complet :**
   ```bash
   docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:v8.30.1 detect --source=/repo --verbose
   # Doit retourner : "no leaks found" (exit code 0)
   ```
2. **Contrôle de l'arbre de travail courant :**
   ```bash
   git diff HEAD..backup-pre-purge -- app/ tests/ scripts/
   # Doit retourner 0 différence (aucun fichier applicatif altéré)
   ```
3. **Exécution de la suite de tests :**
   ```bash
   pytest tests/
   # Doit confirmer : 25 passed
   ```

---

## 4. Résultats du test de validation locale

La procédure ci-dessus a été exécutée et validée sur une copie miroir de test :
- **Temps d'exécution :** 1,69 seconde pour réécrire et compacter les 52 commits.
- **Résultat Gitleaks :**
  ```text
  7:47PM INF 52 commits scanned.
  7:47PM INF scanned ~529019 bytes (529.02 KB) in 880ms
  7:47PM INF no leaks found
  ```
- **Résultat Git diff :** `0` ligne modifiée sur l'arbre de travail applicatif (`app/`, `tests/`, `scripts/`).
- **Tests unitaires et d'intégration :** `25 passed in 9.10s`.

---

## 5. Procédure de rotation des secrets réels (Post-Purge)

Bien que les secrets inventoriés soient des secrets de démonstration et des tokens forgés de pentest, toute purge d'historique en environnement de production exige une rotation systématique :

1. **Clé de signature JWT (`JWT_SECRET`) :**
   - Générer une nouvelle clé cryptographique aléatoire de 256 bits :
     ```bash
     openssl rand -hex 32
     ```
   - Mettre à jour les variables d'environnement des conteneurs (`.env` local, secrets CI/CD GitHub Secrets).
   - Invalider immédiatement toutes les sessions existantes.

2. **Identifiants de base de données (`POSTGRES_PASSWORD`) :**
   - Modifier le mot de passe de l'utilisateur `tenantguard` dans PostgreSQL via `ALTER USER tenantguard WITH PASSWORD '...';`.
   - Mettre à jour la chaîne de connexion `DATABASE_URL`.

3. **Clés API de services tiers (LLM / Cloud) :**
   - Si des clés tierces (ex. Google Gemini API, OpenAI) avaient été commitées en v0 :
     - Se connecter à la console fournisseur (ex. Google AI Studio).
     - Révoquer immédiatement la clé exposée.
     - Générer une nouvelle clé avec des restrictions d'IP et de quotas.
     - Vérifier les journaux d'audit de facturation du fournisseur pour s'assurer de l'absence d'utilisation non autorisée.

---

## 6. Décision requise avant réécriture du remote officiel

> [!IMPORTANT]
> **Statut actuel :**
> - Tag local posé : `backup-pre-purge`.
> - Procédure testée et validée localement avec succès (`0 leak`).
> - Le remote `origin/main` n'a **PAS** été forcé (`git push --force` non exécuté).
