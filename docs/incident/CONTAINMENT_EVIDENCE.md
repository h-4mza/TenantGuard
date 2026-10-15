# Preuves Réelles de Confinement (Containment Evidence)

Ce document consigne la sortie **brute et non reformatée**, copiée telle quelle des requêtes et des journaux de conteneurs (`docker compose logs api`), attestant de l'efficacité et des effets réels des deux mesures de confinement appliquées sur la stack TenantGuard.

---

## 1. Verrouillage du compte 'alice' directement en base de données PostgreSQL

### a. Tentative d'authentification AVANT verrouillage
Requête HTTP :
```http
POST /auth/login HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{"username": "alice", "password": "alice123"}
```

Réponse HTTP brute :
```http
HTTP/1.1 200 OK
date: Wed, 14 Oct 2026 20:27:10 GMT
server: uvicorn
content-length: 318
content-type: application/json
vary: Origin

{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.[PAYLOAD_REDACTED].[SIGNATURE_REDACTED]","token_type":"bearer","user":{"id":1,"tenant_id":1,"username":"alice","email":"alice@acme.com","role":"admin"}}
```

Ligne de log d'audit émise :
```text
tenantguard_api  | {"timestamp": "2026-10-14T20:27:11.328611+00:00", "level": "INFO", "logger": "tenantguard.audit", "event": "AUTH_LOGIN_SUCCESS", "message": "[AUTH_LOGIN_SUCCESS]", "user_id": 1, "username": "alice", "tenant_id": 1, "ip": "172.24.0.1"}
```

---

### b. Commande de verrouillage exécutée en base
```bash
docker compose exec -T db psql -U tenantguard -d tenantguard_db \
  -c "UPDATE users SET hashed_password = 'DISABLED_' || hashed_password WHERE username = 'alice';"
```
Sortie :
```text
UPDATE 1
```

---

### c. Tentative d'authentification APRÈS verrouillage
Requête HTTP :
```http
POST /auth/login HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{"username": "alice", "password": "alice123"}
```

Réponse HTTP brute :
```http
HTTP/1.1 401 Unauthorized
date: Wed, 14 Oct 2026 20:27:11 GMT
server: uvicorn
content-length: 44
content-type: application/json
vary: Origin

{"detail":"Incorrect username or password."}
```

---

### d. Lignes réelles de journaux API (`docker compose logs api | grep AUTH_LOGIN`)
```text
tenantguard_api  | {"timestamp": "2026-10-14T20:27:11.328611+00:00", "level": "INFO", "logger": "tenantguard.audit", "event": "AUTH_LOGIN_SUCCESS", "message": "[AUTH_LOGIN_SUCCESS]", "user_id": 1, "username": "alice", "tenant_id": 1, "ip": "172.24.0.1"}
tenantguard_api  | {"timestamp": "2026-10-14T20:27:11.831212+00:00", "level": "WARNING", "logger": "tenantguard.audit", "event": "AUTH_LOGIN_FAILED", "message": "[AUTH_LOGIN_FAILED]", "username": "alice", "ip": "172.24.0.1"}
```

---

## 2. Révocation globale des sessions actives par rotation de `JWT_SECRET`

> *Note méthodologique :* Conformément au script `scripts/test_containment.sh`, le compte d'alice ayant été préalablement verrouillé en base lors du premier test (section 1), la rotation de secret a été testée avec le jeton de bob comme représentant d'un jeton valide émis avant la rotation ; le mécanisme cryptographique d'invalidation est rigoureusement identique pour le jeton d'alice ou tout autre compte.

### a. Requête AVANT rotation avec le jeton porteur de l'attaquant
Requête HTTP :
```http
GET /documents HTTP/1.1
Host: localhost:8000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c...
```

Réponse HTTP brute :
```http
HTTP/1.1 200 OK
date: Wed, 14 Oct 2026 20:27:11 GMT
server: uvicorn
content-length: 210
content-type: application/json
vary: Origin

[{"id":3,"tenant_id":2,"uploaded_by":2,"filename":"cyberdyne_skynet_defense_specs.txt","file_size":256,"stored_path":"/app/uploads/cyberdyne_skynet_defense_specs.txt","created_at":"2026-10-14T20:22:58.838592"}]
```

---

### b. Commande de rotation et redémarrage du conteneur API
```bash
NEW_SECRET=$(openssl rand -hex 32)
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$NEW_SECRET|" .env
docker compose up -d api
```

Sortie docker compose :
```text
 Container tenantguard_db Running 
 Container tenantguard_api Recreate 
 Container tenantguard_api Recreated 
 Container tenantguard_db Waiting 
 Container tenantguard_db Healthy 
 Container tenantguard_api Starting 
 Container tenantguard_api Started 
```

---

### c. Requête APRÈS rotation avec le même jeton
Requête HTTP :
```http
GET /documents HTTP/1.1
Host: localhost:8000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c...
```

Réponse HTTP brute :
```http
HTTP/1.1 401 Unauthorized
date: Wed, 14 Oct 2026 20:27:20 GMT
server: uvicorn
www-authenticate: Bearer
content-length: 68
content-type: application/json
vary: Origin

{"detail":"Could not validate credentials: invalid token signature"}
```

---

### d. Lignes réelles de `docker compose logs api` sur cette requête
```text
tenantguard_api  | 2026-10-14 20:27:21 [WARNING] [tenantguard.auth] Invalid JWT token provided: Signature verification failed
tenantguard_api  | INFO:     172.24.0.1:58508 - "GET /documents HTTP/1.1" 401 Unauthorized
```

> **Observation technique essentielle :**
> Aucun événement d'audit JSON (`AUTH_TOKEN_EXPIRED` ou autre) n'est émis lors de la présentation d'un jeton à signature invalide.
> Conformément au code de `app/auth.py` (lignes 84-109), seule l'exception `jwt.ExpiredSignatureError` déclenche l'appel à `log_audit("AUTH_TOKEN_EXPIRED", ...)`. L'exception `jwt.InvalidTokenError` consigne uniquement le message d'avertissement texte standard `Invalid JWT token provided: Signature verification failed` sans émettre d'événement d'audit structuré.
