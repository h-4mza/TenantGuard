# Runbook d'Incident : CROSS_TENANT_ACCESS

## 1. Description & Contexte
Ce runbook traite les violations critiques d'étanchéité multi-tenant. Un utilisateur authentifié appartenant à un tenant spécifique tente d'accéder, de visualiser, de télécharger ou de supprimer des documents appartenant à une autre organisation (`DOCUMENT_ACCESS_DENIED`). Cela traduit une tentative d'exploitation IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization).

- **Sévérité :** Critical
- **Tactique MITRE ATT&CK :** Lateral Movement / Privilege Escalation
- **Techniques MITRE ATT&CK :** [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) / [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event="DOCUMENT_ACCESS_DENIED" [5m]))
  ```
- **Seuil d'alerte :** $\ge 3$ refus d'accès documentaire cross-tenant en 5 minutes pour un même `user_id`.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Identifier l'utilisateur et son organisation d'origine
Extraire l'identité du compte et son tenant :
```logql
{container="tenantguard_api"} | json | event="DOCUMENT_ACCESS_DENIED" | user_id="<USER_ID_ALERTE>"
```

### Étape 2 : Analyser les identifiants de documents ciblés
Lister tous les `document_id` ciblés par cet utilisateur :
```logql
sum by (document_id) (count_over_time({container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event="DOCUMENT_ACCESS_DENIED" [15m]))
```
Vérifier dans PostgreSQL à qui appartiennent réellement ces documents :
```bash
# [Non testée] Identification des propriétaires légitimes des documents ciblés
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "SELECT id, filename, tenant_id FROM documents WHERE id IN (1, 2, 3, <DOC_IDS_CIBLES>);"
```

### Étape 3 : Contrôler s'il y a eu fuite de données (Oracle 404 vs 200)
Vérifier impérativement si une requête a réussi à lire ou télécharger un document étranger :
```logql
{container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event =~ "DOCUMENT_VIEW|DOCUMENT_DOWNLOAD"
```
*Note :* Dans TenantGuard v1, les routes appliquent un filtre strict `Document.tenant_id == current_user.tenant_id`. Si une requête sur un document d'un autre tenant a été émise, l'API renvoie HTTP 404 et émet `DOCUMENT_ACCESS_DENIED`. Vérifier qu'aucun événement de succès n'a été émis pour un document d'un autre tenant.

---

## 4. Critères de Faux Positif
1. **Lien hypertexte partagé par erreur :** Un utilisateur a reçu un lien interne direct (ex: `/documents/42`) partagé par un collègue d'un autre tenant et a cliqué dessus par mégarde.
2. **Erreur d'intégration de script client :** Un connecteur API interne a itéré sur un index sans filtrer par tenant.
*Note :* Même en cas d'erreur de clic, une fréquence de $\ge 3$ requêtes en 5 min traduit généralement un balayage intentionnel et doit être investiguée avec rigueur.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P0 (Fuite de données avérée) :** Si un document étranger a pu être lu ou téléchargé. Déclencher immédiatement la notification RGPD et la cellule de crise.
- **Escalade en P1 (Tentative de violation bloquée) :** Si les requêtes ont été bloquées (HTTP 404) mais proviennent d'une sonde délibérée. Confinement immédiat du compte.
- **Clôture :** Si l'utilisateur confirme une erreur de lien unique expliquée de façon crédible.

---

## 6. Mesures de Confinement (Containment)

### Action A : Suspension immédiate du compte utilisateur en base *(Testée)*
Neutraliser instantanément le mot de passe de l'utilisateur malveillant pour couper tout nouvel accès :
```bash
# [Testée] Verrouillage du compte en base de données
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'SUSPENDED_' || hashed_password WHERE id = <USER_ID_ALERTE>;"
```

### Action B : Invalidation immédiate du jeton actif de l'attaquant *(Testée)*
L'application ne disposant pas d'une liste de révocation dynamique de tokens (blacklist), forcer la révocation globale des sessions par rotation de clé :
```bash
# [Testée] Invalidation globale par rotation de clé JWT
# 1. Mettre à jour JWT_SECRET dans le fichier .env
# 2. Recréer l'API pour appliquer la nouvelle variable
docker compose up -d api
```

### Action C : Blocage réseau de l'IP de l'attaquant *(Non testée en local)*
```bash
# [Non testée - Infrastructure Linux / WAF]
iptables -A INPUT -s <IP_ATTAQUANT> -j DROP
```

---

## 7. Éradication & Récupération
1. **Éradication :** Vérifier l'invalidation de la session de l'utilisateur.
2. **Récupération :**
   - Examiner les autorisations du tenant de l'attaquant.
   - S'assurer que le compte demeure suspendu jusqu'à la conclusion de l'audit contractuel.

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Notification de Sécurité] Tentative d'accès non autorisé neutralisée

Madame, Monsieur le Responsable Sécurité,

Nous vous informons qu'un comportement anormal a été détecté et bloqué sur la plateforme TenantGuard.
Un compte utilisateur rattaché à une autre organisation a tenté d'interroger les identifiants de documents suivants, appartenant potentiellement à votre espace : <LISTE_DOCUMENTS>.

Garantie d'intégrité :
Nos mécanismes d'isolation multi-tenant au niveau de la couche applicative et de la base de données ont strictement rejeté l'ensemble de ces requêtes (statut HTTP 404). Aucun document ni aucune métadonnée n'a été exposé.

Mesures conservatoires :
- Le compte initiateur des requêtes a été immédiatement suspendu.
- Les adresses IP sources ont été isolées.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Historique complet des requêtes de l'utilisateur fautif :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>"' \
    --data-urlencode 'limit=500' > evidence_cross_tenant_user_<USER_ID>.json
  ```
- **Copie certifiée des logs de déni d'accès.**
