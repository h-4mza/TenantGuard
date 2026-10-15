# Étude de Cas Technique : Sécurisation, Observabilité & Détection d'un SaaS Multi-Tenant RAG

**Projet :** TenantGuard v1.0  
**Auteur :** Hamza (Ingénierie Cybersécurité & DevSecOps)  
**Dépôt :** [github.com/h-4mza/TenantGuard](https://github.com/h-4mza/TenantGuard)  
**Date :** Octobre 2026  

---

## 1. Contexte & Problématique Métier

Les architectures SaaS B2B modernes combinant plusieurs locataires (*tenants*) et des pipelines d'intelligence artificielle générative (RAG - *Retrieval-Augmented Generation*) présentent une surface d'attaque hybride critique. La compromission de l'isolation logique entre tenants expose directement les entreprises à des fuites de propriété intellectuelle, à de l'espionnage industriel et à des sanctions réglementaires sévères (RGPD).

**TenantGuard** a été conçu pour éprouver le cycle de vie complet de sécurisation d'une telle plateforme :
1. Déploiement d'une version initiale vulnérable instrumentée (v0).
2. Audit offensif indépendant (campagne de pentest documentée).
3. Remédiation défensive en profondeur et mise en place d'une chaîne CI/CD DevSecOps à gates bloquantes.
4. Conception d'un système d'audit structuré et de détection en temps réel (SIEM léger) provisionné en code.
5. Simulation d'incident en conditions réelles, réponse opérationnelle et post-mortem médico-légal blameless.

---

## 2. Modèle de Menace & Constatations du Pentest (v0)

La campagne de pentest offensive initiale a identifié **8 vulnérabilités critiques** réparties sur l'ensemble de la pile applicative (source : [`pentest/report.md`](file:///pentest/report.md)) :
- **Authentification & Session :** Signature JWT reposant sur une clé par défaut triviale (`secret123`) cassable en quelques secondes par dictionnaire (FINDING-01, CVSS 9.1) et désactivation explicite de la vérification d'expiration `verify_exp: False` permettant des attaques par rejeu permanent (FINDING-02, CVSS 8.2).
- **Cloisonnement Applicatif (BOLA / IDOR) :** Absence de validation de l'appartenance tenant sur les routes de consultation/téléchargement documentaire, permettant la fuite intégrale des contrats de concurrents via manipulation du paramètre `tenant_id` ou de l'ID de ressource (FINDING-03 & FINDING-04, CVSS 8.5 / 6.5).
- **Manipulation de Fichiers :** Absence de filtrage d'extensions, absence de limite de taille et vulnérabilité de traversée de répertoire (*Path Traversal*) dans le nom de fichier uploadé (FINDING-05, CVSS 7.5).
- **Sécurité du Pipeline RAG :** Interrogation vectorielle dans ChromaDB sans filtre `where={"tenant_id": ...}` obligatoire, permettant à un utilisateur d'interroger la mémoire sémantique d'un tenant rival (FINDING-06, CVSS 8.5), et absence d'assainissement du prompt utilisateur permettant d'extraire des secrets contextuels par injection de prompt (FINDING-07, CVSS 7.5).
- **Gestion des Secrets :** Identifiants de base de données et clés secrètes versionnés en clair dans le code et les fichiers Compose (FINDING-08, CVSS 9.1).

---

## 3. Architecture Technique & Pipeline DevSecOps (v1.0)

L'architecture repose sur des composants durcis et isolés par conteneurs Docker :

```mermaid
graph TD
    User["Client HTTP / Attaquant"] -->|Port 8000| API["FastAPI Backend (Python 3.11, Non-Root UID 10001)"]
    API -->|Port 5432| DB[("PostgreSQL 15 (Données relationnelles & Comptes)")]
    API -->|Mémoire / FS| Chroma[("ChromaDB (Index vectoriel partitionné)")]
    API -->|Audit JSON stdout| Promtail["Promtail 3.0.0 (Scrape logs conteneurs)"]
    Promtail -->|Push HTTP| Loki["Grafana Loki 3.0.0 (Indexation LogQL)"]
    Loki --> Grafana["Grafana 11.0.0 (Unified Alerting & Dashboards)"]
    Grafana -->|Webhook Alertes POST| Receiver["Alert Receiver (Port local 8088)"]
    
    subgraph CI_CD ["Pipeline DevSecOps (GitHub Actions - Ubuntu 24.04)"]
        SAST["Semgrep (SAST)"]
        SCA["pip-audit (SCA)"]
        Secrets["Gitleaks v8.30.1 (Secrets)"]
        Trivy["Trivy 0.76.0 (Image CRITICAL/HIGH)"]
        DAST["OWASP ZAP (DAST Baseline)"]
        SBOM["Syft (SBOM SPDX)"]
    end
```

### Chaîne de Sécurité Logicielle (CI/CD)
Le workflow GitHub Actions ([`.github/workflows/devsecops.yml`](file:///.github/workflows/devsecops.yml)) s'exécute sur `ubuntu-24.04` avec 6 étapes indépendantes :
1. **SAST (Semgrep) :** Analyse statique avec règles OWASP Top 10, zéro finding bloquant.
2. **SCA (pip-audit) :** Analyse des vulnérabilités de dépendances Python avec justification documentée des CVEs upstream sans correctif disponible.
3. **Secrets (Gitleaks v8.30.1) :** Blocage systématique de tout secret dans l'arbre de travail.
4. **Scan d'Image (Trivy 0.76.0) :** Analyse des vulnérabilités du système d'exploitation de base Alpine/Debian (`--severity CRITICAL,HIGH --ignore-unfixed --exit-code 1`).
5. **DAST (OWASP ZAP Baseline) :** Scan dynamique de l'API en cours d'exécution.
6. **SBOM (Syft v0.24.3) :** Génération de la nomenclature logicielle SPDX-JSON (171 composants archivés).

---

## 4. Détection des Menaces & Grafana Unified Alerting

La détection repose sur la collecte d'événements d'audit structurés au format JSON émis par l'API FastAPI et ingérés par Grafana Loki. Sept règles de détection provisionnées sous forme de code dans `config/grafana/provisioning/alerting/rules.yml` surveillent en continu les comportements anormaux :

| Règle de Détection | Technique MITRE ATT&CK | Sévérité | Condition de Déclenchement | Objectif de Sécurité |
|---|---|---|---|---|
| `BRUTE_FORCE_LOGIN` | T1110 (Brute Force) | High | $\ge 5$ échecs de connexion en 5 min par IP | Détection précoce d'attaque dictionnaire / credential testing |
| `CREDENTIAL_STUFFING` | T1110.004 (Cred Stuffing) | High | $\ge 5$ échecs de connexion avec usernames distincts depuis une IP | Détection de vaporisation de mots de passe |
| `CROSS_TENANT_ACCESS` | T1078 (Valid Accounts / BOLA) | Critical | $\ge 3$ refus `DOCUMENT_ACCESS_DENIED` en 5 min | Détection de tentative d'exploitation IDOR cross-tenant |
| `UPLOAD_ANOMALY` | T1105 / T1190 (Ingress Tool / Exploit) | Medium | $\ge 3$ uploads refusés (extension/taille/traversal) | Détection de fuzzing d'upload malveillant |
| `TOKEN_ABUSE_SUSPECT` | T1528 (Steal Application Token) | High | $\ge 3$ jetons expirés soumis en 5 min | Détection de rejeu de sessions obsolètes |
| `ACCOUNT_TAKEOVER_SUSPECT` | T1078 (Valid Accounts) | Critical | $\ge 3$ échecs suivis d'au moins 1 succès sur même compte | Détection de compromission active de mot de passe |
| `EXFILTRATION_VOLUME` | T1530 (Data from Cloud Storage) | High | $\ge 15$ accès documentaires en 2 min par utilisateur | Détection de collecte et téléchargement massif |

Chaque règle est associée à un tableau de bord Grafana temps réel (`tenantguard-detection-overview`) et à un runbook opérationnel pas-à-pas documenté dans [`docs/runbooks/`](file:///docs/runbooks/).

---

## 5. Simulation d'Incident de Bout en Bout & Métriques Observées

Un scénario d'intrusion réaliste a été joué sur la stack au moyen d'un script d'attaque rejouable ([`scripts/run_incident.sh`](file:///scripts/run_incident.sh)) simulant un attaquant ciblant le tenant Acme Corp :
- **Phase 1 (Reconnaissance) :** Énumération non authentifiée et sondage d'identifiants (12:03:00 - 12:03:15 UTC).
- **Phase 2 (Accès Initial) :** Brute-force sur le compte `alice` (5 échecs), suivi d'un login réussi (12:03:15 - 12:03:40 UTC).
- **Phase 3 (Mouvement Latéral) :** Tentatives répétées d'accès aux documents du tenant rival CyberDyne Systems (12:04:00 - 12:04:20 UTC).
- **Phase 4 (Collecte & Exfiltration) :** Téléchargements en rafale (16 requêtes) et interrogation sémantique agressive via l'API RAG (12:04:20 - 12:04:47 UTC).

### Métriques Clés Mesurées :
- **Temps Moyen de Détection (MTTD) :** **46,5 secondes**.
  - Début de l'attaque brute force : `12:03:00` UTC.
  - Première alerte déclenchée (`BRUTE_FORCE_LOGIN` Firing) : `12:03:46.5` UTC.  
  *(Source : calcul médico-légal consigné dans [`docs/incident/POSTMORTEM.md`](file:///docs/incident/POSTMORTEM.md) et validé dans [`docs/incident/evidence/alerts_received.log`](file:///docs/incident/evidence/alerts_received.log)).*
- **Taux de Détection de la Chaîne d'Attaque :** **100 %**.  
  Les alertes `BRUTE_FORCE_LOGIN`, `ACCOUNT_TAKEOVER_SUSPECT`, `CROSS_TENANT_ACCESS` et `EXFILTRATION_VOLUME` ont toutes basculé en état `Firing` et transmis leurs alertes au récepteur webhook (533 lignes de logs d'alertes collectées).
- **Validation du Confinement Opérationnel :**
  Deux mesures d'urgence ont été appliquées et vérifiées par copies brutes des logs applicatifs (source : [`docs/incident/CONTAINMENT_EVIDENCE.md`](file:///docs/incident/CONTAINMENT_EVIDENCE.md)) :
  1. Verrouillage du compte compromis en base (`is_active = FALSE`) : rejet immédiat des nouvelles authentifications avec code 401 à `12:07:05 UTC`.
  2. Rotation à chaud de `JWT_SECRET` : révocation immédiate du jeton actif détenu par l'attaquant avec rejet HTTP 401 à `12:08:30 UTC`.

---

## 6. Enseignements & Limites Connues de la v1.0

L'exercice de réponse à incident a permis de documenter en toute transparence les axes d'amélioration de la solution :
1. **Angles morts d'audit applicatif :** Seules les signatures expirées émettent un log d'audit JSON (`log_audit`). Les jetons forgés dont la signature est corrompue et les requêtes non authentifiées sont interceptés par le middleware FastAPI avant l'audit, restant invisibles dans Loki (documenté dans [`KNOWN_ISSUES_V0.md`](file:///KNOWN_ISSUES_V0.md)).
2. **Gestion de l'invalidation des sessions :** En l'absence de table de révocation centralisée (Redis / token blacklist), la neutralisation d'un jeton actif volé requiert la rotation globale du secret, affectant l'ensemble des utilisateurs légitimes.
3. **Environnement Réseau :** La dépendance à `request.client.host` nécessite une configuration explicite du reverse proxy (`X-Forwarded-For`) pour éviter l'aveuglement en DMZ.

---

## 7. Preuves Vérifiables du Dépôt

Toutes les métriques et affirmations de cette étude sont directement vérifiables dans le code source :
- Audit offensif initial : [`pentest/report.md`](file:///pentest/report.md)
- Matrice de remédiation : [`KNOWN_ISSUES_V0.md`](file:///KNOWN_ISSUES_V0.md)
- Règles de détection : [`DETECTION.md`](file:///DETECTION.md) & [`config/grafana/provisioning/alerting/rules.yml`](file:///config/grafana/provisioning/alerting/rules.yml)
- Script d'attaque incident : [`scripts/run_incident.sh`](file:///scripts/run_incident.sh)
- Journal brut des alertes reçues : [`docs/incident/evidence/alerts_received.log`](file:///docs/incident/evidence/alerts_received.log)
- Preuves d'investigation LogQL : [`docs/incident/INVESTIGATION.md`](file:///docs/incident/INVESTIGATION.md)
- Preuves de confinement : [`docs/incident/CONTAINMENT_EVIDENCE.md`](file:///docs/incident/CONTAINMENT_EVIDENCE.md)
- Post-mortem blameless : [`docs/incident/POSTMORTEM.md`](file:///docs/incident/POSTMORTEM.md)
- Inventaire et plan de purge Git : [`docs/HISTORY_PURGE.md`](file:///docs/HISTORY_PURGE.md)
