# Post-Mortem de Sécurité : Incident "Opération BlackShard"

**Date de l'incident :** 15 octobre 2026  
**Statut :** Résolu / Post-Mortem Blameless  
**Auteurs :** Équipe de Réponse à Incident (CSIRT / SOC TenantGuard)  
**Classification :** P1 — Incident Majeur de Sécurité  

---

## 1. Résumé Exécutif
Le 15 octobre 2026 à 12:03 UTC, une attaque ciblée en provenance de l'adresse IP `172.24.0.1` a compromis le compte administrateur `alice` appartenant au tenant Acme Corp (Tenant 1) via une attaque par force brute / dictionnaire sur l'endpoint `/auth/login`.  
L'attaquant a ensuite tenté d'accéder aux documents confidentiels d'organisations tierces (CyberDyne Systems), tentatives immédiatement bloquées par l'isolation multi-tenant v1. L'attaquant a ensuite procédé à l'exfiltration massive de 22 lectures/téléchargements du document interne d'Acme Corp (`acme_strategic_acquisition_2026.txt`) et exécuté une requête d'extraction sémantique via le moteur RAG.

L'ensemble des activités hostiles auditées a été détecté en temps réel par les règles Grafana Unified Alerting avec un délai de détection moyen de **46,5 secondes**. Toutes les alertes émises par Grafana ont été capturées fidèlement par le webhook récepteur (`docs/incident/evidence/alerts_received.log`). Les mesures de confinement immédiates testées et validées (verrouillage du compte en base et rotation de la clé maîtresse JWT avec recréation du conteneur API) ont permis de neutraliser l'adversaire et de révoquer l'ensemble des sessions actives (preuves brutes consignées dans `docs/incident/CONTAINMENT_EVIDENCE.md`).

---

## 2. Évaluation de l'Impact
- **Confidentialité :** Compromission restreinte aux documents du tenant Acme Corp (1 document accédé). **Aucune donnée d'autres organisations (CyberDyne ou Initech) n'a été divulguée.**
- **Intégrité :** Aucune modification de document, ni altération de la base relationnelle ou vectorielle.
- **Disponibilité :** Disponibilité nominale maintenue pour tous les autres tenants de la plateforme.

---

## 3. Chronologie des Événements (Horodatages Réels UTC)

| Horodatage UTC | Événement Applicatif | Phase MITRE ATT&CK | Description Technique & Source |
|---|---|---|---|
| **12:03:41Z** | Sondage `/health` (200) et `/documents/*` (401) | **Reconnaissance (T1595)** | *(Source : horodatage script — aucun événement d'audit émis pour les requêtes non authentifiées)* Sondage de l'API et énumération non authentifiée. |
| **12:03:59Z** | `AUTH_LOGIN_FAILED` (x5) | **Accès Initial (T1110)** | *(Source : logs d'audit)* 5 tentatives successives de mot de passe invalide sur `alice`. |
| **12:04:02Z** | `AUTH_LOGIN_SUCCESS` | **Accès Initial (T1078)** | *(Source : logs d'audit)* Connexion réussie pour `alice` (user_id=1, tenant_id=1). Émission du JWT. |
| **12:04:26Z** | `DOCUMENT_ACCESS_DENIED` (x4) | **Mouvement Latéral (T1078/T1190)** | *(Source : logs d'audit)* 4 tentatives d'accès au document étranger id=3 (CyberDyne) bloquées (HTTP 404). |
| **12:04:47Z** | `DOCUMENT_LIST` | **Découverte (T1083)** | *(Source : logs d'audit)* Énumération des documents du tenant Acme Corp. |
| **12:04:47Z** | `DOCUMENT_VIEW` (doc id=2) | **Collecte & Exfiltration (T1530)** | **Premier log d'exfiltration réel** (`12:04:47.710Z`, prouvé par requête LogQL). |
| **12:04:47Z** à **12:04:50Z** | `DOCUMENT_VIEW` & `DOWNLOAD` (x22) | **Collecte & Exfiltration (T1530)** | *(Source : logs d'audit)* 22 accès documentaires en rafale sur le document id=2 d'Acme Corp. |
| **12:04:50Z** | **Alerte `BRUTE_FORCE_LOGIN`** | Détection SOC | Déclenchement de l'alerte High (`startsAt: 2026-10-15T12:04:50Z`, cf. `alerts_received.log`). |
| **12:04:50Z** | **Alerte `ACCOUNT_TAKEOVER_SUSPECT`** | Détection SOC | Déclenchement de l'alerte Critical (`startsAt: 2026-10-15T12:04:50Z`, cf. `alerts_received.log`). |
| **12:04:50Z** | **Alerte `CROSS_TENANT_ACCESS`** | Détection SOC | Déclenchement de l'alerte Critical (`startsAt: 2026-10-15T12:04:50Z`, cf. `alerts_received.log`). |
| **12:04:52Z** | `RAG_QUERY` | **Exfiltration (T1119)** | *(Source : logs d'audit)* Extraction sémantique via le LLM (`12:04:52.884Z`). |
| **12:05:50Z** | **Alerte `EXFILTRATION_VOLUME`** | Détection SOC | Déclenchement de l'alerte Medium (`startsAt: 2026-10-15T12:05:50Z`, cf. `alerts_received.log`). |
| **Confinement** | Verrouillage compte PostgreSQL | **Confinement (Containment)** | *(Testée — reproduit dans `CONTAINMENT_EVIDENCE.md`)* `UPDATE users SET hashed_password = 'DISABLED_'...`. Login ultérieur rejeté avec 401 Unauthorized (`AUTH_LOGIN_FAILED`). |
| **Confinement** | Rotation `JWT_SECRET` + recreate API | **Confinement (Containment)** | *(Testée — reproduit dans `CONTAINMENT_EVIDENCE.md`)* `sed -i ... .env` et `docker compose up -d api`. Requête avec jeton émis avant rotation rejetée avec 401 ("invalid token signature"). |

---

## 4. Analyse des Délais de Détection (MTTD)

Le calcul s'appuie strictement sur le premier timestamp réel issu des logs d'audit pour chaque événement hostile :

| Règle d'Alerte | Sévérité | Début réel de l'action hostile (Logs) | Déclenchement de l'alerte (`startsAt`) | Délai de Détection Mesuré |
|---|---|---|---|---|
| **BRUTE_FORCE_LOGIN** | High | `12:03:59Z` (`AUTH_LOGIN_FAILED`) | `12:04:50Z` | **51 secondes** |
| **ACCOUNT_TAKEOVER_SUSPECT** | Critical | `12:04:02Z` (`AUTH_LOGIN_SUCCESS`) | `12:04:50Z` | **48 secondes** |
| **CROSS_TENANT_ACCESS** | Critical | `12:04:26Z` (`DOCUMENT_ACCESS_DENIED`) | `12:04:50Z` | **24 secondes** |
| **EXFILTRATION_VOLUME** | Medium | `12:04:47Z` (Premier log `DOCUMENT_VIEW` doc 2) | `12:05:50Z` | **63 secondes** |

- **Requête LogQL de preuve du début d'exfiltration :**  
  `{container="tenantguard_api"} | json | user_id="1" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD"`  
  -> Premier résultat renvoyé : timestamp `2026-10-15T12:04:47.710324+00:00` (événement `DOCUMENT_VIEW` sur `document_id=2`).
- **Moyenne MTTD (Mean Time To Detect) :** **46,5 secondes** ((51 + 48 + 24 + 63) / 4).

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
- **Précision des alertes Grafana Unified Alerting :** Les 4 règles correspondant aux actions hostiles auditées ont toutes transité à l'état `Firing` dès leur première fenêtre d'évaluation de 1 minute.
- **Réactivité du confinement réel :** La neutralisation du compte en base et l'invalidation globale de session ont été testées avec succès sur la stack et consignées dans `docs/incident/CONTAINMENT_EVIDENCE.md`.

---

## 7. Ce qui a manqué (Angles Morts & Limites)
- **Invisibilité des jetons invalides ou falsifiés :**  
  Conformément à `app/auth.py`, seule l'exception `jwt.ExpiredSignatureError` émet un événement d'audit `AUTH_TOKEN_EXPIRED`. L'exception `jwt.InvalidTokenError` (jeton forgé ou devenu invalide après rotation de secret) n'émet **aucun événement d'audit JSON**, consignant seulement un log texte standard dans uvicorn. Ni `TOKEN_ABUSE` ni aucune autre règle n'a de visibilité sur les rejeux de faux tokens.
- **Invisibilité des requêtes non authentifiées (Reconnaissance) :**  
  Les requêtes HTTP 401 ("Authentication required") sur `/documents` n'émettent aucun événement d'audit structuré. La Phase 1 de reconnaissance est donc totalement absente des flux Loki (invisible, et non "sous le seuil").
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
| **ACT-03** | **P1** | **Émettre un événement d'audit structuré `AUTH_TOKEN_INVALID`** lors des rejets de tokens à signature invalide (`jwt.InvalidTokenError`), avec règle d'alerte associée. *(Action future)* | `@backend-eng` | J+5 |
| **ACT-04** | **P1** | **Émettre un événement d'audit structuré `AUTH_UNAUTHENTICATED_ACCESS`** lors des requêtes 401 non authentifiées sur les routes protégées pour tracer la reconnaissance, avec règle d'alerte associée. *(Action future)* | `@backend-eng` | J+5 |
| **ACT-05** | **P1** | Intégrer l'authentification multifacteur (TOTP MFA / WebAuthn) pour les comptes administrateurs. | `@backend-eng` | J+14 |
| **ACT-06** | **P1** | Enrichir l'événement `RAG_QUERY` avec les métadonnées de volume et taille de réponse sans journaliser les secrets métier. | `@sec-lead` | J+7 |
| **ACT-07** | **P2** | Déployer un reverse proxy frontal Nginx / WAF avec module ModSecurity et gestion stricte des en-têtes `X-Forwarded-For`. | `@infra-sre` | J+21 |

---

## 9. Cartographie MITRE ATT&CK de l'Incident

| Phase de l'Attaque | Tactique MITRE | Technique & ID | Détection Associée |
|---|---|---|---|
| **Phase 1** | Reconnaissance | Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/)) | Non audité dans Loki (visible uniquement dans les logs bruts HTTP de reverse proxy) |
| **Phase 2** | Credential Access | Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/)) | `BRUTE_FORCE_LOGIN` |
| **Phase 2** | Defense Evasion | Valid Accounts ([T1078](https://attack.mitre.org/techniques/T1078/)) | `ACCOUNT_TAKEOVER_SUSPECT` |
| **Phase 3** | Lateral Movement | Exploit Public App ([T1190](https://attack.mitre.org/techniques/T1190/)) | `CROSS_TENANT_ACCESS` |
| **Phase 4** | Collection | Data from Cloud Storage ([T1530](https://attack.mitre.org/techniques/T1530/)) | `EXFILTRATION_VOLUME` |
| **Phase 4** | Exfiltration | Automated Collection ([T1119](https://attack.mitre.org/techniques/T1119/)) | Audit `RAG_QUERY` |

