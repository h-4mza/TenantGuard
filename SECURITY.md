# Politique de Sécurité (Security Policy) — TenantGuard

## 1. Cadre Pédagogique & Avertissement

> [!NOTE]
> **Projet d'Étude & Portfolio :**  
> **TenantGuard** est un projet de démonstration et un cas d'étude en cybersécurité applicative, DevSecOps et réponse à incident, conçu dans le cadre d'un portfolio technique.
>
> Les identifiants, mots de passe et clés d'exemple mentionnés dans la documentation ou les scripts de simulation (`alice123`, `bob123`, `charlie123`, etc.) sont destinés **exclusivement aux tests locaux et aux évaluations de démonstration** sur `localhost`. Aucun environnement de production réel n'utilise ces données.

---

## 2. Versions Supportées

Seule la dernière version stable (`v1.x`) bénéficie des correctifs de sécurité et du support actif.

| Version | Statut du support | Notes |
|:-------:|:-----------------:|:------|
| **1.0.x** | ✅ **Actif (Supporté)** | Version durcie, auditée et monitorée. |
| **0.1.x** | ❌ **Obsolète / Non supporté** | Version initiale délibérément vulnérable (historique d'audit). |

---

## 3. Signalement d'une Vulnérabilité

Si vous découvrez une faille de sécurité ou une faiblesse imprévue dans l'architecture durcie de TenantGuard, nous vous remercions de nous en faire part de manière responsable.

### Procédure de divulgation coordonnée :
1. **Ne pas ouvrir d'issue publique** : Pour éviter l'exposition d'utilisateurs potentiels ou de démonstrateurs, ne créez pas de ticket GitHub public contenant des détails d'exploitation.
2. **Signalement privé GitHub** :
   - Utilisez exclusivement la fonctionnalité de signalement de vulnérabilité privé de GitHub accessible via l'onglet **Security > Report a vulnerability** du dépôt GitHub. Cela permet d'échanger de manière confidentielle et chiffrée avec le mainteneur sans exposer de détails techniques publiquement.
3. **Contenu recommandé du rapport** :
   - Description précise de la vulnérabilité et de son impact potentiel.
   - Étapes de reproduction détaillées ou script de preuve de concept (PoC).
   - Version et environnement concernés (OS, version Docker, configuration).
   - Proposition de correctif ou d'atténuation si disponible.

### Engagement et Délais de Traitement :
- **Accusé de réception initial :** Sous 48 heures ouvrées.
- **Évaluation et confirmation :** Sous 5 jours ouvrés.
- **Publication d'un correctif :** Selon la criticité de la faille (sous 14 jours pour une faille critique).

---

## 4. Pratiques de Sécurité Implémentées

La version active intègre les contrôles de sécurité suivants :
- **Contrôle d'accès & Isolation :** Vérification stricte des revendications JWT (`tenant_id`, `role`), rejet des accès cross-tenant par code HTTP 404 neutre.
- **Gestion des Secrets :** Entropie minimale imposée (256 bits pour `JWT_SECRET`), pas de valeurs par défaut sensibles dans le code, validation en CI par Gitleaks.
- **Pipeline DevSecOps :** Analyse statique (Semgrep), analyse des vulnérabilités de dépendances (pip-audit), analyse d'images conteneurs (Trivy), génération de SBOM (Syft), scan dynamique DAST (OWASP ZAP Baseline).
- **Principe de Moindre Privilège :** Conteneur applicatif exécuté sous utilisateur non-root (UID 10001), ports d'observabilité restreints à l'interface de bouclage `127.0.0.1`.
- **Détection & Audit :** Journalisation d'audit JSON structurée, règles d'alerte Grafana Unified Alerting basées sur LogQL et mappées à MITRE ATT&CK.
