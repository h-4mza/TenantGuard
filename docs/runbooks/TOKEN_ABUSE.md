# Runbook d'Incident : TOKEN_ABUSE

## 1. Description & Contexte
Ce runbook traite les requêtes rejetées avec un statut HTTP 401 en raison de jetons JWT expirés (`AUTH_TOKEN_EXPIRED`). Une concentration anormale de requêtes avec des jetons périmés depuis une même adresse IP peut traduire une attaque par rejeu (*Token Replay*), l'utilisation d'outils automatisés rejouant des captures de trafic antérieures, ou un vol d'identifiant stale.

- **Sévérité :** Medium
- **Tactique MITRE ATT&CK :** Credential Access / Defense Evasion
- **Technique MITRE ATT&CK :** [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_TOKEN_EXPIRED" [5m]))
  ```
- **Seuil d'alerte :** $\ge 5$ événements `AUTH_TOKEN_EXPIRED` en 5 minutes pour une même adresse IP.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Isoler l'IP source et la distribution des requêtes
Vérifier le volume d'erreurs générées :
```logql
sum by (ip) (count_over_time({container="tenantguard_api"} | json | event="AUTH_TOKEN_EXPIRED" [15m]))
```

### Étape 2 : Identifier le nom d'utilisateur extrait du jeton expiré
L'API TenantGuard effectue un décodage non vérifié à des fins de télémétrie sur les jetons expirés pour renseigner le champ `username` dans l'événement d'audit. Exécuter :
```logql
sum by (username) (count_over_time({container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event="AUTH_TOKEN_EXPIRED" [15m]))
```

### Étape 3 : Vérifier si l'adresse IP a obtenu ou utilisé un jeton valide
Contrôler si l'IP suspecte s'est connectée avec succès ou a réussi à appeler des routes protégées :
```logql
{container="tenantguard_api"} | json | ip="<IP_SUSPECTE>" | event =~ "AUTH_LOGIN_SUCCESS|DOCUMENT_VIEW|DOCUMENT_DOWNLOAD|RAG_QUERY"
```

---

## 4. Critères de Faux Positif
1. **Client API ou intégration tierce désynchronisée :** Une application cliente ayant omis de rafraîchir son jeton JWT avant échéance et bouclant sur une route API.
2. **Onglet de navigateur ouvert :** Un utilisateur légitime dont la session a expiré pendant qu'une page rafraîchit en arrière-plan.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P2 (Rejeu / Token Stolen) :** Si les requêtes proviennent d'une IP externe inconnue sans rapport avec l'organisation du compte ciblé.
- **Clôture :** Si l'IP provient du réseau interne et que l'utilisateur a réactualisé sa session immédiatement après.

---

## 6. Mesures de Confinement (Containment)

### Action A : Invalidation globale des jetons par rotation du secret *(Testée)*
Si une suspicion de fuite de tokens existe, invalider immédiatement l'ensemble des jetons en circulation en changeant la clé maîtresse :
```bash
# [Testée] Rotation de JWT_SECRET
# Mettre à jour JWT_SECRET dans l'environnement et recréer l'API
docker compose up -d api
```

### Action B : Blocage IP au pare-feu *(Non testée en local)*
```bash
# [Non testée - Infrastructure Linux / WAF]
iptables -A INPUT -s <IP_SUSPECTE> -j DROP
```

### Action C : Verrouillage préventif du compte ciblé en base *(Testée)*
```bash
# [Testée] Verrouillage du compte utilisateur
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'LOCKED_' || hashed_password WHERE username = '<USERNAME_EXTRAIT>';"
```

---

## 7. Éradication & Récupération
1. **Éradication :** Vérifier que les requêtes avec le jeton expiré sont définitivement rejetées (HTTP 401).
2. **Récupération :**
   - Assister le client ou l'utilisateur pour qu'il s'authentifie à nouveau via `/auth/login` afin d'obtenir un jeton frais.
   - Vérifier le bon paramétrage des délais d'expiration (15 minutes par défaut).

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Avis Technique] Nombre anormal de requêtes avec jeton expiré

Bonjour,

Nous constatons un volume inhabituel de requêtes API rejetées pour jeton expiré (HTTP 401) depuis l'adresse IP <IP_SUSPECTE>, associées au compte utilisateur <USERNAME_EXTRAIT>.
Si vous utilisez un script ou une application cliente automatisée, merci de vérifier que votre mécanisme de ré-authentification sur /auth/login fonctionne correctement.
Si vous n'êtes pas à l'origine de ces requêtes, nous vous invitons à réinitialiser votre mot de passe immédiatement.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Capture des requêtes 401 pour jeton expiré :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | event="AUTH_TOKEN_EXPIRED" | ip="<IP_SUSPECTE>"' > evidence_token_abuse_<IP>.json
  ```
