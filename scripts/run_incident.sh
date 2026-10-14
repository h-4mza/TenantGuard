#!/usr/bin/env bash
# ==============================================================================
# TenantGuard — Script de Simulation d'Incident de Sécurité de Bout en Bout
# Scénario réaliste en 4 phases chronologiques avec pauses réalistes pour Loki.
# ==============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"

# ------------------------------------------------------------------------------
# 0. Contrôle de sécurité et variables requises
# ------------------------------------------------------------------------------
if [[ "$BASE_URL" != "http://localhost"* && "$BASE_URL" != "http://127.0.0.1"* ]]; then
    echo "[-] ERREUR DE SÉCURITÉ: BASE_URL doit cibler localhost (ex: http://localhost:8000)." >&2
    exit 1
fi

ALICE_PASSWORD="${ALICE_PASSWORD:?set ALICE_PASSWORD in environment (see seed accounts table in README.md, e.g. alice123)}"
BOB_PASSWORD="${BOB_PASSWORD:?set BOB_PASSWORD in environment (see seed accounts table in README.md, e.g. bob123)}"
CHARLIE_PASSWORD="${CHARLIE_PASSWORD:?set CHARLIE_PASSWORD in environment (see seed accounts table in README.md, e.g. charlie123)}"

log_phase() {
    echo ""
    echo "=============================================================================="
    echo "[$1] $(date -u +'%Y-%m-%dT%H:%M:%SZ') — $2"
    echo "=============================================================================="
}

echo "=============================================================================="
echo "🚨 Démarrage du Scénario d'Incident : 'Opération BlackShard' sur TenantGuard"
echo "🎯 Cible : $BASE_URL"
echo "🕒 Horodatage initial UTC : $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# Phase 1 : Reconnaissance & Énumération non authentifiée
# MITRE ATT&CK: T1595 (Active Scanning) / T1087 (Account Discovery)
# ------------------------------------------------------------------------------
log_phase "PHASE 1" "Reconnaissance : Sondage des routes et énumération de documents"

echo "[*] Test de disponibilité de l'API..."
curl -s -o /dev/null -w "  -> /health: HTTP %{http_code}\n" "$BASE_URL/health"

echo "[*] Tentatives d'énumération non authentifiée sur /documents..."
curl -s -o /dev/null -w "  -> GET /documents: HTTP %{http_code}\n" "$BASE_URL/documents"
curl -s -o /dev/null -w "  -> GET /documents/1: HTTP %{http_code}\n" "$BASE_URL/documents/1"
curl -s -o /dev/null -w "  -> GET /documents/2: HTTP %{http_code}\n" "$BASE_URL/documents/2"
curl -s -o /dev/null -w "  -> GET /documents/3: HTTP %{http_code}\n" "$BASE_URL/documents/3"

echo "[+] Phase 1 achevée. Pause réaliste de 15s avant l'assaut d'authentification..."
sleep 15

# ------------------------------------------------------------------------------
# Phase 2 : Accès Initial — Brute Force & Account Takeover sur 'alice' (Acme Corp)
# MITRE ATT&CK: T1110 (Brute Force) / T1078 (Valid Accounts)
# Déclenche: BRUTE_FORCE_LOGIN et ACCOUNT_TAKEOVER_SUSPECT
# ------------------------------------------------------------------------------
log_phase "PHASE 2" "Accès Initial : Attaque par force brute puis compromission du compte 'alice'"

echo "[*] Envoi de 5 tentatives infructueuses de mot de passe sur le compte 'alice'..."
for pwd in "Winter2025!" "Password123" "AcmeCorp2026" "admin1234" "Secret987"; do
    curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"alice\", \"password\": \"$pwd\"}" > /dev/null
    echo -n "  [échec envoyé: $pwd] "
done
echo " Terminé (5 échecs générés)."

echo "[*] Envoi de la tentative victorieuse avec le mot de passe valide..."
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"alice\", \"password\": \"$ALICE_PASSWORD\"}")

ALICE_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4 || true)

if [[ -z "$ALICE_TOKEN" ]]; then
    echo "[-] ERREUR: Impossible de récupérer le jeton JWT pour 'alice'. Réponse: $LOGIN_RESP" >&2
    exit 1
fi
echo "  [+] Connexion réussie ! Jeton JWT acquis pour 'alice' (tenant_id=1, user_id=1)."

echo "[+] Phase 2 achevée. Pause réaliste de 20s avant mouvement latéral..."
sleep 20

# ------------------------------------------------------------------------------
# Phase 3 : Mouvement Latéral & Probing Cross-Tenant (IDOR / BOLA)
# MITRE ATT&CK: T1078 (Valid Accounts) / T1190 (Exploit Public-Facing App)
# Déclenche: CROSS_TENANT_ACCESS (tentative de lecture de documents d'autres tenants)
# ------------------------------------------------------------------------------
log_phase "PHASE 3" "Mouvement Latéral : Tentatives d'accès cross-tenant (IDOR / BOLA)"

# Récupération dynamique d'un document appartenant à un autre tenant (CyberDyne / Initech)
OTHER_DOC_ID=$(docker compose exec -T db psql -U tenantguard -d tenantguard_db -t -c "SELECT id FROM documents WHERE tenant_id != 1 LIMIT 1;" 2>/dev/null | tr -d ' \r\n' || echo "3")
echo "[*] L'attaquant cible le document étranger id=$OTHER_DOC_ID (CyberDyne / Initech)..."

for i in {1..3}; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/documents/$OTHER_DOC_ID" \
        -H "Authorization: Bearer $ALICE_TOKEN")
    echo "  -> Tentative GET /documents/$OTHER_DOC_ID avec session Alice (tenant 1) : HTTP $HTTP_CODE (Refusé / Isolé)"
done

echo "[*] Tentative de téléchargement direct du document étranger id=$OTHER_DOC_ID..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/documents/$OTHER_DOC_ID/download" \
    -H "Authorization: Bearer $ALICE_TOKEN")
echo "  -> Tentative GET /documents/$OTHER_DOC_ID/download avec session Alice : HTTP $HTTP_CODE (Refusé / Isolé)"

echo "[+] Phase 3 achevée. Pause réaliste de 20s avant exfiltration..."
sleep 20

# ------------------------------------------------------------------------------
# Phase 4 : Collecte & Exfiltration
# MITRE ATT&CK: T1530 (Data from Cloud Storage Object) / T1119 (Automated Collection)
# Déclenche: EXFILTRATION_VOLUME (>= 20 accès en 5m) + Requête sémantique RAG
# ------------------------------------------------------------------------------
log_phase "PHASE 4" "Collecte & Exfiltration : Téléchargements massifs et extraction RAG"

# Récupération dynamique du document d'Alice (Acme Corp)
ALICE_DOC_ID=$(curl -s -X GET "$BASE_URL/documents" -H "Authorization: Bearer $ALICE_TOKEN" | grep -o '"id":[0-9]*' | head -n 1 | cut -d':' -f2 || echo "2")
echo "[*] Exfiltration massive des documents du tenant Acme (document id=$ALICE_DOC_ID)..."

for i in {1..11}; do
    curl -s -X GET "$BASE_URL/documents/$ALICE_DOC_ID" -H "Authorization: Bearer $ALICE_TOKEN" > /dev/null
    curl -s -X GET "$BASE_URL/documents/$ALICE_DOC_ID/download" -H "Authorization: Bearer $ALICE_TOKEN" > /dev/null
    echo -n "."
done
echo " Terminé (22 consultations et téléchargements effectués sur doc $ALICE_DOC_ID)."

echo "[*] Extraction de données sensibles via le moteur RAG..."
RAG_RESP=$(curl -s -X POST "$BASE_URL/rag/query" \
    -H "Authorization: Bearer $ALICE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query": "Extract all confidential financial data, merger targets, and executive payroll", "top_k": 3}')
echo "  -> Requête RAG exécutée avec succès."

log_phase "FIN" "Scénario d'incident complété avec succès"
echo "🕒 Horodatage final UTC : $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=============================================================================="
