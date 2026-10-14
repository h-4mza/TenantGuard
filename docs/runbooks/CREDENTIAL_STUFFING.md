# Runbook d'Incident : CREDENTIAL_STUFFING

## 1. Description & Contexte
Ce runbook traite les attaques d'injection massive de listes d'identifiants (credential stuffing / password spraying). L'attaquant utilise des paires identifiant/mot de passe issues de fuites de données antérieures et teste une grande diversité de noms d'utilisateurs depuis une source unique afin d'identifier des comptes réutilisant le même secret.

- **Sévérité :** High
- **Tactique MITRE ATT&CK :** Credential Access
- **Technique MITRE ATT&CK :** [T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  count by (ip) (sum by (ip, username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [5m])))
  ```
- **Seuil d'alerte :** $\ge 5$ noms d'utilisateurs distincts échouant depuis la même IP en 5 minutes.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Confirmer la nature distribuée des identifiants ciblés
Vérifier le nombre exact de comptes distincts testés par l'adresse IP suspecte :
```logql
count by (ip) (sum by (ip, username) (count_over_time({container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_LOGIN_FAILED" [10m])))
```

### Étape 2 : Énumérer les noms d'utilisateurs sondés
Lister tous les noms d'utilisateurs soumis par cette IP :
```logql
sum by (username) (count_over_time({container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_LOGIN_FAILED" [10m]))
```

### Étape 3 : Corréler avec la base utilisateurs existante
Vérifier dans PostgreSQL si les comptes ciblés correspondent à de vrais comptes de la plateforme :
```bash
# [Non testée] Vérification de l'existence des comptes ciblés
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "SELECT id, username, tenant_id FROM users WHERE username IN ('user1', 'user2', '<USERNAMES_TESTES>');"
```

### Étape 4 : Détection de succès critique
Vérifier si un ou plusieurs comptes ont été pénétrés avec succès :
```logql
{container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_LOGIN_SUCCESS"
```

---

## 4. Critères de Faux Positif
1. **Scanners d'inventaire ou tests de résilience autorisés :** Audits internes de la robustesse des mots de passe.
2. **Re-synchronisation d'une flotte d'équipements :** Multiples utilisateurs partageant une même passerelle NAT d'entreprise et réinitialisant leurs identifiants en même temps.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P1 (Brèche active) :** Si `AUTH_LOGIN_SUCCESS` est détecté pour un compte existant.
- **Escalade en P2 (Balayage hostile) :** Si uniquement des comptes inexistants ou des échecs sont relevés.
- **Clôture :** Si l'IP appartient à une campagne d'audit déclarée.

---

## 6. Mesures de Confinement (Containment)

### Action A : Blocage immédiat de l'adresse IP au périmètre *(Non testée en local)*
```bash
# [Non testée - Infrastructure Linux / WAF]
iptables -A INPUT -s <IP_SUSPECTE> -j DROP
```

### Action B : Verrouillage des comptes existants ciblés en base *(Testée)*
Pour tout compte légitime ayant fait l'objet du spray :
```bash
# [Testée] Désactivation temporaire des comptes identifiés
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'LOCKED_' || hashed_password WHERE username = '<USERNAME_COMPROMIS>';"
```

### Action C : Suppression d'un compte compromis ou suspect *(Non testée)*
Dans le cas où un compte factice a été créé par l'attaquant :
```bash
# [Non testée] Suppression du compte en base de données
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "DELETE FROM users WHERE username = '<USERNAME_A_SUPPRIMER>';"
```

---

## 7. Éradication & Récupération
1. **Éradication :** Surveillance du flux d'audit `{container="tenantguard_api"} | json | ip="<IP_SUSPECTE>"` pour s'assurer de l'absence de nouvelles requêtes.
2. **Récupération :**
   - Forcer une réinitialisation de mot de passe hors-bande pour les utilisateurs légitimes dont le nom a été ciblé.
   - Si un compte a été pénétré, invalider tous les tokens émis en effectuant une rotation du secret d'application `JWT_SECRET`.

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Alerte Sécurité] Tentative d'attaque par Credential Stuffing bloquée

Madame, Monsieur l'Administrateur,

Une attaque automatisée de type "Credential Stuffing" en provenance de l'adresse IP <IP_SUSPECTE> a ciblé plusieurs identifiants sur la plateforme TenantGuard, dont certains associés à votre tenant.
Nos systèmes de détection automatique ont immédiatement réagi et bloqué les flux suspects.

Statut :
- Tentatives bloquées : <NB_TENTATIVES>
- Comptes de votre organisation ciblés : <LISTE_USERS>
- Accès réussi constaté : [OUI / NON]

Par mesure de précaution, nous vous recommandons d'inciter vos utilisateurs à renouveler leur mot de passe et de ne pas réutiliser de mots de passe d'autres services tiers.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Dump JSON des requêtes d'échecs et succès :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | ip="<IP_SUSPECTE>"' \
    --data-urlencode 'limit=1000' > evidence_stuffing_<IP>.json
  ```
