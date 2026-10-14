#!/usr/bin/env bash
# ==============================================================================
# TenantGuard — Script de Simulation d'Attaques & Déclenchement d'Alertes
# Reproduit de façon déterministe les scénarios mappés à MITRE ATT&CK.
# ==============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"

# ------------------------------------------------------------------------------
# Vérification de sécurité : Cible localhost exclusivement
# ------------------------------------------------------------------------------
if [[ "$BASE_URL" != "http://localhost"* && "$BASE_URL" != "http://127.0.0.1"* ]]; then
    echo "[-] ERREUR DE SÉCURITÉ: BASE_URL doit cibler localhost (ex: http://localhost:8000 ou http://127.0.0.1:8000)." >&2
    echo "[-] Cible reçue: '$BASE_URL' — Exécution refusée." >&2
    exit 1
fi

# Mots de passe issus de variables d'environnement obligatoires (comptes seed: alice123, bob123, charlie123)
ALICE_PASSWORD="${ALICE_PASSWORD:?set ALICE_PASSWORD in environment (see seed accounts table in README.md, e.g. alice123)}"
BOB_PASSWORD="${BOB_PASSWORD:?set BOB_PASSWORD in environment (see seed accounts table in README.md, e.g. bob123)}"
CHARLIE_PASSWORD="${CHARLIE_PASSWORD:?set CHARLIE_PASSWORD in environment (see seed accounts table in README.md, e.g. charlie123)}"

echo "=============================================================================="
echo "🛡️  Démarrage de la simulation d'attaques TenantGuard"
echo "🎯 Cible: $BASE_URL"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. BRUTE_FORCE_LOGIN (T1110 - High)
# Seuil: >= 5 échecs de connexion en 5m pour une même IP
# ------------------------------------------------------------------------------
echo -e "\n[+] 1/7 Déclenchement: BRUTE_FORCE_LOGIN (T1110)..."
for i in {1..6}; do
    curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "victim_bf", "password": "wrong_password_attempt"}' > /dev/null
    echo -n "."
done
echo " Terminé (6 échecs envoyés pour 'victim_bf')."

# ------------------------------------------------------------------------------
# 2. CREDENTIAL_STUFFING (T1110.004 - High)
# Seuil: >= 5 usernames distincts en échec depuis une même IP en 5m
# ------------------------------------------------------------------------------
echo -e "\n[+] 2/7 Déclenchement: CREDENTIAL_STUFFING (T1110.004)..."
for user in admin_test root_user dev_operator guest_account test_user scanner_bot; do
    curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$user\", \"password\": \"StuffedPass2026!\"}" > /dev/null
    echo -n "."
done
echo " Terminé (6 usernames distincts en échec)."

# ------------------------------------------------------------------------------
# Récupération des tokens d'authentification Alice et Bob
# ------------------------------------------------------------------------------
ALICE_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"alice\", \"password\": \"$ALICE_PASSWORD\"}" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4 || true)

BOB_TOKEN=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"bob\", \"password\": \"$BOB_PASSWORD\"}" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4 || true)

if [[ -z "$ALICE_TOKEN" || -z "$BOB_TOKEN" ]]; then
    echo "[-] Échec d'authentification pour Alice ou Bob. Vérifiez que la base est initialisée." >&2
    exit 1
fi

# Récupération dynamique d'un document appartenant à Alice (Tenant 1)
ALICE_DOC_ID=$(curl -s -X GET "$BASE_URL/documents" -H "Authorization: Bearer $ALICE_TOKEN" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2 || true)
if [[ -z "$ALICE_DOC_ID" ]]; then
    ALICE_DOC_ID="2"
fi

# ------------------------------------------------------------------------------
# 3. CROSS_TENANT_ACCESS (T1078 / T1190 - Critical)
# Seuil: >= 3 DOCUMENT_ACCESS_DENIED en 5m pour un même user_id (IDOR inter-tenant)
# ------------------------------------------------------------------------------
echo -e "\n[+] 3/7 Déclenchement: CROSS_TENANT_ACCESS (IDOR / BOLA)..."
# Bob (Tenant 2) tente d'accéder au document d'Alice (Tenant 1)
for i in {1..4}; do
    curl -s -X GET "$BASE_URL/documents/$ALICE_DOC_ID" \
        -H "Authorization: Bearer $BOB_TOKEN" > /dev/null
    echo -n "."
done
echo " Terminé (4 accès refusés IDOR pour user_id=2 sur doc $ALICE_DOC_ID)."

# ------------------------------------------------------------------------------
# 4. UPLOAD_ABUSE (T1105 - Medium)
# Seuil: >= 3 UPLOAD_REJECTED en 10m pour un même user_id
# ------------------------------------------------------------------------------
echo -e "\n[+] 4/7 Déclenchement: UPLOAD_ABUSE (Extensions interdites / fichiers rejetés)..."
for bad_ext in malicious.exe webshell.php exploit.sh trojan.bin; do
    echo "malicious payload content" > "/tmp/$bad_ext"
    curl -s -X POST "$BASE_URL/documents/upload" \
        -H "Authorization: Bearer $ALICE_TOKEN" \
        -F "file=@/tmp/$bad_ext" > /dev/null
    rm -f "/tmp/$bad_ext"
    echo -n "."
done
echo " Terminé (4 téléversements interdits rejetés pour user_id=1)."

# ------------------------------------------------------------------------------
# 5. TOKEN_ABUSE (T1528 - Medium)
# Seuil: >= 5 AUTH_TOKEN_EXPIRED en 5m pour une même IP
# ------------------------------------------------------------------------------
echo -e "\n[+] 5/7 Déclenchement: TOKEN_ABUSE (Jetons JWT expirés)..."
# Génération d'un jeton avec date d'expiration dans le passé via le conteneur API
EXPIRED_TOKEN=$(docker compose exec -T api python -c "from app.auth import JWT_SECRET; import jwt; print(jwt.encode({'sub': 'attacker', 'exp': 1000000000}, JWT_SECRET, algorithm='HS256'))" 2>/dev/null | tr -d '\r' || true)

if [[ -z "$EXPIRED_TOKEN" ]]; then
    echo "[-] ERREUR: Impossible de générer le jeton JWT expiré via le conteneur 'api'. Assurez-vous que le service 'api' est démarré." >&2
    exit 1
fi

for i in {1..6}; do
    curl -s -X GET "$BASE_URL/auth/me" \
        -H "Authorization: Bearer $EXPIRED_TOKEN" > /dev/null
    echo -n "."
done
echo " Terminé (6 requêtes envoyées avec jeton JWT expiré)."

# ------------------------------------------------------------------------------
# 6. ACCOUNT_TAKEOVER_SUSPECT (T1110 - Critical)
# Seuil: >= 3 échecs sur un username suivis d'un succès sur ce même username en 10m
# ------------------------------------------------------------------------------
echo -e "\n[+] 6/7 Déclenchement: ACCOUNT_TAKEOVER_SUSPECT (Brute force suivi de succès)..."
# 3 échecs sur le compte Charlie
for i in {1..3}; do
    curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "charlie", "password": "wrong_guess_password"}' > /dev/null
    echo -n "."
done
# 1 succès immédiat sur le compte Charlie
curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"charlie\", \"password\": \"$CHARLIE_PASSWORD\"}" > /dev/null
echo ". Terminé (3 échecs puis 1 succès pour 'charlie')."

# ------------------------------------------------------------------------------
# 7. EXFILTRATION_VOLUME (T1530 - Medium)
# Seuil: >= 20 DOCUMENT_DOWNLOAD ou DOCUMENT_VIEW en 5m pour un même user_id
# ------------------------------------------------------------------------------
echo -e "\n[+] 7/7 Déclenchement: EXFILTRATION_VOLUME (Téléchargements / consultations en rafale)..."
for i in {1..22}; do
    curl -s -X GET "$BASE_URL/documents/$ALICE_DOC_ID" \
        -H "Authorization: Bearer $ALICE_TOKEN" > /dev/null
    echo -n "."
done
echo " Terminé (22 consultations de documents par user_id=1)."

echo -e "\n=============================================================================="
echo "✅  Toutes les simulations d'attaques ont été exécutées avec succès !"
echo "=============================================================================="
