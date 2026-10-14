# Runbook d'Incident : BRUTE_FORCE_LOGIN

## 1. Description & Contexte
Ce runbook régit la réponse à incident face à des tentatives répétées et infructueuses d'authentification provenant d'une même adresse IP. Cette activité indique une attaque par force brute par dictionnaire ou attaque par pulvérisation visant à deviner les identifiants d'un ou plusieurs comptes SaaS TenantGuard.

- **Sévérité :** High
- **Tactique MITRE ATT&CK :** Credential Access
- **Technique MITRE ATT&CK :** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [5m]))
  ```
- **Seuil d'alerte :** $\ge 5$ échecs d'authentification sur une fenêtre glissante de 5 minutes pour une même adresse IP.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Identifier l'adresse IP source et le volume d'échecs
Exécuter la requête LogQL suivante dans Grafana Explore pour isoler l'activité de l'IP :
```logql
sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [15m]))
```

### Étape 2 : Analyser les comptes ciblés et la chronologie des requêtes
Extraire la liste exhaustive des noms d'utilisateurs testés par cette IP :
```logql
sum by (username) (count_over_time({container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_LOGIN_FAILED" [15m]))
```

### Étape 3 : Vérifier si une connexion a réussi (Recherche de brèche)
Rechercher impérativement tout événement `AUTH_LOGIN_SUCCESS` émis par cette IP ou pour l'un des comptes ciblés :
```logql
{container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_LOGIN_SUCCESS"
```
```logql
{container="tenantguard_api"} | json | username="<USERNAME_CIBLE>" | event="AUTH_LOGIN_SUCCESS"
```

---

## 4. Critères de Faux Positif
L'alerte peut être classée comme faux positif si et seulement si :
1. **Erreur utilisateur légitime :** L'adresse IP appartient au sous-réseau interne de l'organisation ou à un VPN connu, et un employé valide a saisi plusieurs fois un mot de passe erroné avant de le réinitialiser.
2. **Test d'assurance qualité ou pentest planifié :** L'activité a été déclarée et autorisée par écrit dans le cadre d'un test d'intrusion interne.
3. **Dysfonctionnement applicatif :** Un script d'intégration ou un client API tente de se reconnecter avec des identifiants expirés.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P1 (Incident Majeur) :** Si un événement `AUTH_LOGIN_SUCCESS` est découvert pour l'un des comptes ciblés depuis l'IP attaquante. Activer immédiatement le runbook `ACCOUNT_TAKEOVER_SUSPECT`.
- **Escalade en P2 (Attaque en cours sans compromission) :** Si les échecs continuent à haute cadence mais qu'aucun login n'a réussi. Appliquer le confinement réseau.
- **Clôture :** Si l'origine est confirmée comme une erreur légitime d'un collaborateur interne.

---

## 6. Mesures de Confinement (Containment)

Voici les actions réalisables aujourd'hui sur l'application dans son état actuel :

### Action A : Verrouillage du compte ciblé en base de données *(Testée)*
Si un compte utilisateur précis est violemment attaqué, verrouiller temporairement son mot de passe directement dans PostgreSQL pour interdire toute connexion ultérieure :
```bash
# [Testée] Désactivation du mot de passe de l'utilisateur ciblé
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'LOCKED_' || hashed_password WHERE username = '<USERNAME_CIBLE>';"
```

### Action B : Blocage de l'adresse IP au niveau réseau / pare-feu *(Non testée en local)*
Ajouter une règle de rejet sur le pare-feu de l'hôte Linux ou le proxy frontal Nginx :
```bash
# [Non testée - environnement Linux/Production] Blocage iptables
iptables -A INPUT -s <IP_SUSPECTE> -j DROP
```
*Note d'architecture :* TenantGuard étant actuellement exécuté en environnement conteneurisé sans proxy frontal de production, le blocage IP s'effectue au niveau de l'infrastructure d'accueil.

### Action C : Invalidation globale de sessions par rotation de secret *(Testée)*
Si une suspicion de fuite de session existe, forcer la révocation globale des jetons JWT en modifiant `JWT_SECRET` :
```bash
# [Testée] Rotation du secret JWT et redémarrage de l'API
# 1. Remplacer JWT_SECRET dans .env avec une nouvelle clé >= 32 caractères
# 2. Recréer le service API pour appliquer la variable d'environnement
docker compose up -d api
```

---

## 7. Éradication & Récupération
1. **Éradication :** Confirmer via les logs Loki que les flux d'authentification malveillants ont cessé.
2. **Récupération :**
   - Si le compte a été verrouillé en base, générer un nouveau mot de passe robuste et rétablir le compte :
     ```bash
     # [Non testée] Réinitialisation d'un mot de passe sécurisé via script de hachage
     docker compose exec -T api python -c "from app.auth import hash_password; from app.database import SessionLocal; from app.models import User; db=SessionLocal(); u=db.query(User).filter_by(username='<USERNAME_CIBLE>').first(); u.hashed_password=hash_password('<NOUVEAU_MOT_DE_PASSE>'); db.commit(); print('Mot de passe mis à jour')"
     ```
   - Forcer la réinitialisation du mot de passe par l'utilisateur légitime lors de son prochain accès.

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Alerte Sécurité] Tentatives de connexion anormales détectées sur votre compte TenantGuard

Madame, Monsieur l'Administrateur,

Notre centre opérationnel de sécurité (SOC) a détecté une série de tentatives de connexion infructueuses visant le(s) compte(s) associé(s) à votre organisation : <USERNAME_CIBLE>.
Origine IP suspecte : <IP_SUSPECTE>
Période : <DATE_HEURE_DEBUT_UTC> à <DATE_HEURE_FIN_UTC>

Mesures préventives appliquées :
- Blocage préventif des flux suspects.
- Verrouillage de sécurité du compte concerné.

Aucune compromission de vos documents multi-tenants n'a été constatée. Nous vous invitons à contacter notre support pour définir un nouveau mot de passe fort.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Extraction des logs d'audit Loki au format JSON :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | ip="<IP_SUSPECTE>"' \
    --data-urlencode 'start=<TIMESTAMP_DEBUT>' \
    --data-urlencode 'end=<TIMESTAMP_FIN>' > evidence_brute_force_<IP>.json
  ```
- **Dump de l'état de la table `users` au moment de l'incident.**
