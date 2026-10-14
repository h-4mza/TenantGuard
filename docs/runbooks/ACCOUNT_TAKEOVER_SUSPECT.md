# Runbook d'Incident : ACCOUNT_TAKEOVER_SUSPECT

## 1. Description & Contexte
Ce runbook traite l'alerte la plus critique de la chaîne d'authentification : une connexion réussie (`AUTH_LOGIN_SUCCESS`) survenant sur un compte utilisateur ayant subi au moins 3 échecs consécutifs d'authentification (`AUTH_LOGIN_FAILED`) dans un intervalle de 10 minutes. Ce motif indique la compromission réussie d'un compte suite à une attaque par force brute ou dictionnaire.

- **Sévérité :** Critical
- **Tactique MITRE ATT&CK :** Initial Access / Persistence
- **Technique MITRE ATT&CK :** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  (sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_FAILED" [10m])) >= 3)
  and
  (sum by (username) (count_over_time({container="tenantguard_api"} | json | event="AUTH_LOGIN_SUCCESS" [10m])) >= 1)
  ```
- **Seuil d'alerte :** $\ge 3$ échecs de connexion et $\ge 1$ succès de connexion pour le même nom d'utilisateur dans une fenêtre de 10 minutes.
- **Délai d'évaluation :** 1 minute (for: 0s).
- **Limite technique LogQL :** La règle compare deux compteurs sur la même fenêtre de 10 min, sans garantir l'ordre ; un succès antérieur aux échecs la déclenche aussi.

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Identifier le compte ciblé et comparer les adresses IP
Rechercher l'historique de l'utilisateur concerné pour comparer l'IP des échecs et l'IP du succès :
```logql
{container="tenantguard_api"} | json | username="<USERNAME_CIBLE>" | event =~ "AUTH_LOGIN_FAILED|AUTH_LOGIN_SUCCESS"
```
- Si l'IP du succès diffère de l'IP des échecs (ou provient d'un pays / ASN anonyme), la compromission est quasi certaine.
- Si les IPs sont identiques, vérifier s'il s'agit d'un collaborateur ayant simplement oublié temporairement son mot de passe.

### Étape 2 : Identifier le premier succès après la séquence d'échecs
Trouver l'horodatage exact UTC du premier succès pour borner la fenêtre de compromission :
```logql
{container="tenantguard_api"} | json | username="<USERNAME_CIBLE>" | event="AUTH_LOGIN_SUCCESS"
```

### Étape 3 : Auditer immédiatement les actions post-compromission
Vérifier l'intégralité des actions entreprises avec cette session :
```logql
{container="tenantguard_api"} | json | user_id="<USER_ID_COMPROMIS>"
```
Vérifier en particulier :
- Les documents consultés ou téléchargés (`DOCUMENT_VIEW`, `DOCUMENT_DOWNLOAD`).
- Les tentatives d'accès aux documents d'autres organisations (`DOCUMENT_ACCESS_DENIED`).
- Les requêtes sémantiques RAG posées (`RAG_QUERY`).

---

## 4. Critères de Faux Positif
1. **Oubli de mot de passe légitime :** L'utilisateur légitime a fait 3 ou 4 fautes de frappe depuis son poste habituel avant de retrouver le bon mot de passe.
2. **Gestionnaire de mots de passe mal configuré :** Un trousseau d'accès tentant d'anciennes versions de clés avant de proposer la clé valide.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P0 (Compromission Active) :** Dès lors que l'IP est inconnue ou que des actions suspectes post-authentification ont été observées.
- **Clôture :** Si l'utilisateur confirme oralement ou par canal hors-bande qu'il s'agissait de sa propre erreur de saisie sans anomalie post-connexion.

---

## 6. Mesures de Confinement Immédiat (Containment)

### Action A : Verrouillage immédiat du compte compromis en base *(Testée)*
Interdire toute nouvelle connexion en altérant le hachage du mot de passe dans PostgreSQL :
```bash
# [Testée] Verrouillage du compte compromis
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'COMPROMISED_' || hashed_password WHERE username = '<USERNAME_COMPROMIS>';"
```

### Action B : Révocation immédiate du jeton actif par rotation de secret *(Testée)*
L'application ne disposant pas d'une liste de révocation dynamique de tokens (blacklist), forcer la révocation globale des sessions par rotation de clé :
```bash
# [Testée] Invalidation globale des jetons par rotation du JWT_SECRET
# 1. Remplacer JWT_SECRET par un nouveau secret fort dans .env
# 2. Recréer l'API pour appliquer la variable
docker compose up -d api
```

### Action C : Blocage de l'IP attaquante au pare-feu *(Non testée en local)*
```bash
# [Non testée - Infrastructure Linux / WAF]
iptables -A INPUT -s <IP_ATTAQUANT> -j DROP
```

---

## 7. Éradication & Récupération
1. **Éradication :**
   - Terminer tous les processus et sessions associés au compte compromis.
   - S'assurer que le compte demeure verrouillé jusqu'à la réinitialisation complète.
2. **Récupération :**
   - Transmettre un mot de passe temporaire à usage unique par canal sécurisé distinct (SMS / appel téléphonique vérifié).
   - Obliger le renouvellement du mot de passe au premier login.
   - Auditer les documents accédés pour vérifier si des données ont été altérées ou exfiltrées.

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [URGENT - SÉCURITÉ] Incident d'accès non autorisé sur le compte <USERNAME_COMPROMIS>

Madame, Monsieur le Responsable Sécurité,

Notre équipe de sécurité a détecté et interrompu un accès illégitime sur le compte utilisateur <USERNAME_COMPROMIS> rattaché à votre organisation.
Chronologie :
- Tentatives d'intrusion infructueuses : <DATE_HEURE_UTC>
- Accès réussi suspect : <DATE_HEURE_UTC> depuis l'adresse IP <IP_ATTAQUANT>.

Mesures immédiates prises par TenantGuard :
- Révocation immédiate de la session et des jetons d'accès.
- Verrouillage administratif du compte en base de données.
- Blocage réseau de l'adresse IP d'origine.

Périmètre des données consultées :
Notre audit des logs indique que l'attaquant a accédé aux éléments suivants : <LISTE_DOCUMENTS_VUS>.
Aucune donnée des autres organisations n'a été corrompue.

Nous nous tenons à votre entière disposition pour coordonner la réinitialisation des accès de votre collaborateur.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Journal complet de la session compromise (de l'attaque à la révocation) :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | username="<USERNAME_COMPROMIS>"' > evidence_ato_user_<USERNAME>.json
  ```
- **Rapport de requêtes post-authentification du `user_id`.**
