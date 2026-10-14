# Post-Mortem de Sécurité : Incident "Opération BlackShard"

**Date de l'incident :** 14 octobre 2026  
**Statut :** Résolu / Post-Mortem Blameless  
**Auteurs :** Équipe de Réponse à Incident (CSIRT / SOC TenantGuard)  
**Classification :** P1 — Incident Majeur de Sécurité  

---

## 1. Résumé Exécutif
Le 14 octobre 2026 à 20:07 UTC, une attaque ciblée en provenance de l'adresse IP `172.24.0.1` a compromis le compte administrateur `alice` appartenant au tenant Acme Corp (Tenant 1) via une attaque par force brute / dictionnaire sur l'endpoint `/auth/login`.  
L'attaquant a ensuite tenté d'accéder aux documents confidentiels d'organisations tierces (CyberDyne Systems), tentatives immédiatement bloquées par l'isolation multi-tenant v1. L'attaquant a ensuite procédé à l'exfiltration massive de 22 lectures/téléchargements du document interne d'Acme Corp (`acme_strategic_acquisition_2026.txt`) et exécuté une requête d'extraction sémantique via le moteur RAG.

L'ensemble des activités hostiles a été détecté en temps réel par les règles Grafana Unified Alerting avec un délai de détection moyen de **42 secondes**. Les mesures de confinement immédiates (verrouillage du compte en base et rotation de la clé maîtresse JWT) ont permis de neutraliser l'adversaire et de révoquer l'ensemble des sessions actives.

---

## 2. Évaluation de l'Impact
- **Confidentialité :** Compromission restreinte aux documents du tenant Acme Corp (1 document accédé). **Aucune donnée d'autres organisations (CyberDyne ou Initech) n'a été divulguée.**
- **Intégrité :** Aucune modification de document, ni altération de la base relationnelle ou vectorielle.
- **Disponibilité :** Disponibilité nominale maintenue pour tous les autres tenants de la plateforme.

---

## 3. Chronologie des Événements (Horodatages Réels UTC)

| Horodatage UTC | Événement Applicatif | Phase MITRE ATT&CK | Description Technique |
|---|---|---|---|
| **20:06:59Z** | `GET /health` & `/documents/*` (401) | **Reconnaissance (T1595)** | Sondage de l'API et tentative d'énumération non authentifiée. |
| **20:07:15Z** | `AUTH_LOGIN_FAILED` (x5) | **Accès Initial (T1110)** | 5 tentatives successives de mot de passe invalide sur `alice`. |
| **20:07:18Z** | `AUTH_LOGIN_SUCCESS` | **Accès Initial (T1078)** | Connexion réussie pour `alice` (user_id=1, tenant_id=1). Émission du JWT. |
| **20:07:38Z** | `DOCUMENT_ACCESS_DENIED` (x4) | **Mouvement Latéral (T1078/T1190)** | Tentatives d'accès au document id=3 (CyberDyne) bloquées (HTTP 404). |
| **20:07:59Z** | `DOCUMENT_LIST` | **Découverte (T1083)** | Énumération des documents du tenant Acme Corp. |
| **20:08:00Z** | **Alerte `BRUTE_FORCE_LOGIN`** | Détection SOC | Déclenchement de l'alerte High (5 échecs en 5 min). |
| **20:08:00Z** | **Alerte `ACCOUNT_TAKEOVER_SUSPECT`** | Détection SOC | Déclenchement de l'alerte Critical (5 échecs suivis d'un succès). |
| **20:08:00Z** | **Alerte `CROSS_TENANT_ACCESS`** | Détection SOC | Déclenchement de l'alerte Critical (4 refus d'accès cross-tenant). |
| **20:08:01Z** | `DOCUMENT_VIEW` & `DOWNLOAD` (x22) | **Collecte & Exfiltration (T1530)** | 22 accès en rafale au document id=2 d'Acme Corp. |
| **20:08:17Z** | `RAG_QUERY` | **Exfiltration (T1119)** | Extraction sémantique via le LLM. |
| **20:09:00Z** | **Alerte `EXFILTRATION_VOLUME`** | Détection SOC | Déclenchement de l'alerte Medium (22 accès en 5 min). |
| **20:10:00Z** | UPDATE users (PostgreSQL) | **Confinement (Containment)** | Verrouillage du compte `alice` (`DISABLED_`). Login ultérieur refusé. |
| **20:10:30Z** | Rotation de `JWT_SECRET` | **Confinement (Containment)** | Régénération de la clé maîtresse. Tous les tokens de session sont révoqués. |

---

## 4. Analyse des Délais de Détection (MTTD)

| Règle d'Alerte | Sévérité | Début de l'action hostile | Déclenchement de l'alerte | Délai de Détection Mesuré |
|---|---|---|---|---|
| **BRUTE_FORCE_LOGIN** | High | 20:07:15Z | 20:08:00Z | **45 secondes** |
| **ACCOUNT_TAKEOVER_SUSPECT** | Critical | 20:07:18Z (Succès) | 20:08:00Z | **42 secondes** |
| **CROSS_TENANT_ACCESS** | Critical | 20:07:38Z | 20:08:00Z | **22 secondes** |
| **EXFILTRATION_VOLUME** | Medium | 20:07:59Z | 20:09:00Z | **61 secondes (1 min 01s)** |

*Moyenne MTTD (Mean Time To Detect) :* **42,5 secondes**.

---

## 5. Analyse de Cause Racine (Root Cause Analysis - RCA)
1. **Absence de politique de verrouillage de compte ou de limitation de débit (Rate-Limiting) sur `/auth/login` :**  
   L'API acceptait un nombre illimité de requêtes par seconde sans ralentissement exponentiel (*tarpitting*) ni blocage temporaire d'IP au niveau applicatif.
2. **Vulnérabilité du mot de passe utilisateur :**  
   Le mot de passe initial de démonstration figurait dans un dictionnaire standard d'attaque.
3. **Absence d'authentification multifacteur (MFA/2FA) :**  
   L'accès initial repose uniquement sur un secret partagé statique.

---

## 6. Ce qui a bien fonctionné
- **Efficacité de l'isolation multi-tenant v1 :** 100% des requêtes cross-tenant ont été bloquées au niveau de la couche SQLAlchemy (`filter(Document.tenant_id == current_user.tenant_id)`), préservant totalement les autres tenants.
- **Télémétrie d'audit structurée JSON :** Tous les événements critiques ont été enrichis avec `user_id`, `tenant_id`, `ip` et `document_id`, permettant une investigation immédiate dans Loki sans ambiguïté.
- **Précision des alertes Grafana Unified Alerting :** Les 4 règles correspondant aux actions hostiles ont toutes transité à l'état `Firing` dès leur première fenêtre d'évaluation de 1 minute.
- **Réactivité du confinement :** La neutralisation du compte en base et l'invalidation globale de session ont pris effet instantanément.

---

## 7. Ce qui a manqué (Angles Morts & Limites)
- **Mécanisme natif de révocation de jeton individuel :**  
  L'application ne dispose pas d'une liste de révocation (blacklist Redis ou table de révocation JWT) ; pour invalider la session de l'attaquant, l'équipe a dû procéder à une rotation globale de `JWT_SECRET`, invalidant par ricochet les sessions des utilisateurs légitimes.
- **Visibilité sur le contenu des réponses RAG :**  
  La réponse textuelle formulée par Gemini/Mock n'étant pas enregistrée dans le log d'audit, l'équipe n'a pu évaluer le volume exact d'informations confidentielles synthétisées.
- **Rate-limiting défensif :**  
  L'exfiltration de 22 documents a pu se faire en rafale sans déclencher de throttling applicatif.

---

## 8. Plan d'Actions Correctives (Corrective Action Items)

| ID | Priorité | Action Corrective | Responsable Fictif | Échéance |
|---|---|---|---|---|
| **ACT-01** | **P0** | Implémenter un rate-limiting strict par IP et par compte sur `/auth/login` (ex: `slowapi` / Redis token bucket). | `@backend-eng` | J+3 |
| **ACT-02** | **P0** | Développer un endpoint et un intercepteur de révocation de jetons individuels (blacklist basée sur le claim `jti`). | `@sec-lead` | J+7 |
| **ACT-03** | **P1** | Intégrer l'authentification multifacteur (TOTP MFA / WebAuthn) pour les comptes administrateurs. | `@backend-eng` | J+14 |
| **ACT-04** | **P1** | Enrichir l'événement `RAG_QUERY` avec les métadonnées de volume et taille de réponse sans journaliser les secrets métier. | `@sec-lead` | J+7 |
| **ACT-05** | **P2** | Déployer un reverse proxy frontal Nginx / WAF avec module ModSecurity et gestion stricte des en-têtes `X-Forwarded-For`. | `@infra-sre` | J+21 |

---

## 9. Cartographie MITRE ATT&CK de l'Incident

| Phase de l'Attaque | Tactique MITRE | Technique & ID | Détection Associée |
|---|---|---|---|
| **Phase 1** | Reconnaissance | Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/)) | Logs d'accès HTTP 401 |
| **Phase 2** | Credential Access | Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/)) | `BRUTE_FORCE_LOGIN` |
| **Phase 2** | Defense Evasion | Valid Accounts ([T1078](https://attack.mitre.org/techniques/T1078/)) | `ACCOUNT_TAKEOVER_SUSPECT` |
| **Phase 3** | Lateral Movement | Exploit Public App ([T1190](https://attack.mitre.org/techniques/T1190/)) | `CROSS_TENANT_ACCESS` |
| **Phase 4** | Collection | Data from Cloud Storage ([T1530](https://attack.mitre.org/techniques/T1530/)) | `EXFILTRATION_VOLUME` |
| **Phase 4** | Exfiltration | Automated Collection ([T1119](https://attack.mitre.org/techniques/T1119/)) | Audit `RAG_QUERY` |
