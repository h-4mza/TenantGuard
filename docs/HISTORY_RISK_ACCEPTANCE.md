# Acceptation des Risques Liés à l'Historique Git (FINDING-08)

> [!NOTE]
> **Décision d'architecture et de gouvernance :**  
> Conformément à l'analyse de risque menée sur le projet TenantGuard, l'historique Git n'a **pas été réécrit** sur le dépôt officiel.  
> Ce document formalise l'inventaire des 22 occurrences détectées, les justifications techniques de l'acceptation du risque, la mise en place de la baseline de détection Gitleaks, et conserve en annexe le plan technique de purge éprouvé localement.

---

## 1. Inventaire Exhaustif des Secrets dans l'Historique

L'analyse de l'historique complet (**54 commits scannés**, ~596 Ko analysés) via `gitleaks detect --source=. --redact --verbose` recense **22 occurrences** de chaînes sensibles (correspondant à 10 valeurs distinctes) :

| # | Commit (abrév.) | Fichier | Règle Gitleaks | Ligne | Empreinte / Valeur Masquée | Classification & Justification |
|---|-----------------|---------|----------------|-------|----------------------------|--------------------------------|
| 1 | `0f1ed0f` | `scripts/simulate_attacks.sh` | `jwt` | 117 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...xCs` | **Secret de démonstration documenté** (faux JWT expiré codé en dur pour test d'intrusion avant Bloc 5) |
| 2 | `aedda6e` | `pentest/findings/FINDING-01-jwt-weak-secret.md` | `jwt` | 35 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...k8I` | **Secret de pentest documenté** (jeton forgé avec la clé v0 comme preuve de concept) |
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
| 16 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `generic-api-key` | 52 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / PoC** (code trésorerie fictif du document seed v0) |
| 17 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `generic-api-key` | 55 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / PoC** (code trésorerie fictif du document seed v0) |
| 18 | `ae7e15e` | `pentest/findings/FINDING-07-rag-prompt-injection.md` | `jwt` | 22 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (jeton test prompt injection) |
| 19 | `ae7e15e` | `pentest/report.md` | `jwt` | 90 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 20 | `ae7e15e` | `pentest/report.md` | `jwt` | 94 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...eQ` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 21 | `ae7e15e` | `pentest/report.md` | `jwt` | 103 | `eyJhbGciOiJIUzI1Ni...[REDACTED]...w0` | **Secret de pentest documenté** (tableau récapitulatif des jetons v0) |
| 22 | `d063fd3` | `app/main.py` | `generic-api-key` | 32 | `ACMESECRET...[REDACTED]...2026` | **Donnée de démonstration / Faux positif** (texte fictif inséré dans le document de trésorerie Acme au démarrage de la v0) |

---

## 2. Justification de l'Acceptation du Risque

Le risque lié à la conservation de ces éléments dans l'historique des commits a été formellement accepté pour les raisons suivantes :

1. **Absence de secret de production ou de clé réelle :**  
   Aucune clé API réelle (AWS, Google Cloud, OpenAI, Stripe, etc.) n'a jamais été commitée dans le dépôt. Tous les identifiants présents sont des valeurs de laboratoire conçues expressément pour des simulations sur `localhost`.
2. **Invalidation cryptographique complète en v1.0 :**  
   L'application durcie (v1.0) impose un secret `JWT_SECRET` aléatoire de 256 bits généré lors du déploiement. Tous les jetons JWT présents dans l'historique ont été signés avec l'ancienne clé triviale `secret123` ; ils sont donc rejetés immédiatement avec une erreur HTTP 401 (`Invalid JWT token`).
3. **Mots de passe et secrets externalisés :**  
   L'ensemble des secrets requis pour l'exécution (`JWT_SECRET`, `POSTGRES_PASSWORD`, `GRAFANA_ADMIN_PASSWORD`) est désormais injecté via des variables d'environnement non versionnées. Les valeurs par défaut ont été retirées du code et des fichiers Compose.
4. **Contrôle continu en intégration continue (CI) :**  
   Le pipeline DevSecOps vérifie systématiquement l'absence de tout nouveau secret dans l'arbre de travail via Gitleaks.
5. **Baseline Gitleaks opérationnelle :**  
   Le fichier `.gitleaks-baseline.json` (qui ne contient aucune valeur en clair grâce à l'option `--redact`) consigne ces 22 empreintes d'historique. L'exécution de la commande de scan d'historique :
   ```bash
   docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:v8.30.1 detect --source=/repo --baseline-path=/repo/.gitleaks-baseline.json --redact --verbose
   ```
   retourne strictement **`0 leak found`** (code de sortie `0`).

---

## 3. Annexe : Procédure Technique de Purge (Pour Référence)

Si une réécriture d'historique devait être entreprise à l'avenir, la procédure suivante a été testée et validée dans un clone miroir temporaire :

### A. Limites inhérentes à une purge Git sur GitHub
Une réécriture d'historique Git (`git-filter-repo` / `git filter-branch`) présente des limites opérationnelles critiques qu'il convient de connaître :
- **Persistance des commits par SHA sur GitHub :** GitHub conserve en cache les objets Git orphelins. Même après un `git push --force`, un commit écrasé reste souvent accessible directement par son URL web (`https://github.com/.../commit/<SHA>`) jusqu'à ce que le cache soit vidé par une demande de maintenance au support GitHub.
- **Préservation dans les forks et les Pull Requests :** Tout fork public existant et toutes les références internes de Pull Requests (`refs/pull/*`) conservent l'historique non réécrit.
- **Invalidation de tous les clones locaux :** Tous les collaborateurs doivent jeter leurs clones existants et recloner le dépôt pour éviter de réintroduire l'ancien historique lors d'un push ultérieur.

### B. Procédure étape par étape dans un clone miroir
```bash
# 1. Cloner en miroir dans un répertoire temporaire
git clone --mirror https://github.com/h-4mza/TenantGuard.git /tmp/tenantguard-mirror.git
cd /tmp/tenantguard-mirror.git

# 2. Créer le fichier de substitution expressions.txt
# Ne JAMAIS commiter ce fichier ; utiliser des correspondances ciblées
cat << 'EOF' > expressions.txt
secret123==>[REDACTED_DEV_SECRET]
tenantguard_secret==>[REDACTED_POSTGRES_PASSWORD]
ACMESECRET2026==>[REDACTED_SEED_DATA]
TOPSECRET2026==>[REDACTED_SEED_DATA]
EOF

# 3. Exécuter git-filter-repo
python -m git_filter_repo --replace-text expressions.txt --force

# 4. Vérifier la propreté de l'historique complet
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:v8.30.1 detect --source=/repo --verbose
# Résultat attendu : no leaks found

# 5. Application au remote officiel (uniquement après validation formelle de l'équipe) :
# git push origin --force --all
# git push origin --force --tags
```
