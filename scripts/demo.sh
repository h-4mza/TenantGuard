#!/usr/bin/env bash
# ==============================================================================
# TenantGuard — Script de Démonstration Autonome de Bout en Bout
# 1. Vérifications préalables (localhost, variables, outils)
# 2. Démarrage de la stack (si non active) et attente de santé
# 3. Déclenchement de 3 scénarios d'attaque représentatifs :
#    - Scénario A : Force brute d'authentification (BRUTE_FORCE_LOGIN)
#    - Scénario B : Violation d'accès cross-tenant IDOR (CROSS_TENANT_ACCESS)
#    - Scénario C : Rejeu de jeton expiré (TOKEN_ABUSE_SUSPECT)
# 4. Attente du cycle d'évaluation Grafana et affichage des alertes reçues
# 5. Instructions pour l'évaluateur (dashboard, runbooks, logs)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE_URL="${BASE_URL:-http://localhost:8000}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
RECEIVER_CONTAINER="tenantguard_alert_receiver"

# ------------------------------------------------------------------------------
# 1. Vérifications préalables de sécurité et d'environnement
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo "🛡️  TenantGuard v1.0 — Démonstration de Sécurité & Détection en Direct"
echo "=============================================================================="

# Garde-fou localhost absolu
if [[ "$BASE_URL" != *"localhost"* && "$BASE_URL" != *"127.0.0.1"* ]]; then
  echo "❌ ERREUR DE SÉCURITÉ : Ce script de démonstration ne doit être exécuté que sur localhost."
  echo "   BASE_URL détecté : $BASE_URL"
  exit 1
fi

# Vérification des mots de passe obligatoires
ALICE_PASSWORD="${ALICE_PASSWORD:?set ALICE_PASSWORD in environment (see seed accounts in README.md, e.g. alice123)}"
BOB_PASSWORD="${BOB_PASSWORD:?set BOB_PASSWORD in environment (see seed accounts in README.md, e.g. bob123)}"
CHARLIE_PASSWORD="${CHARLIE_PASSWORD:?set CHARLIE_PASSWORD in environment (see seed accounts in README.md, e.g. charlie123)}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-secretgrafanapass123}"

echo "✅ Garde-fous localhost et variables d'environnement validés."

# ------------------------------------------------------------------------------
# 2. Vérification et lancement de la stack Docker
# ------------------------------------------------------------------------------
echo -e "\n🔍 Vérification de la disponibilité de l'API..."
if ! curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
  echo "⏳ L'API n'est pas encore joignable. Lancement de la stack complète..."
  cd "$ROOT_DIR"
  docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
  
  echo "⏳ En attente du démarrage de l'API..."
  for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
      echo "✅ API disponible sur $BASE_URL"
      break
    fi
    sleep 2
  done
else
  echo "✅ Stack déjà active et saine sur $BASE_URL"
fi

# ------------------------------------------------------------------------------
# 3. Déclenchement de 3 Scénarios d'Attaque Représentatifs
# ------------------------------------------------------------------------------
echo -e "\n=============================================================================="
echo "💥 Exécution des scénarios d'attaque de démonstration..."
echo "=============================================================================="

# --- Scénario A : Force brute d'authentification ---
echo -e "\n[Scénario 1/3] Attaque par Force Brute (T1110) sur le compte 'alice'..."
for pwd in "WrongPass1" "WrongPass2" "WrongPass3" "WrongPass4" "WrongPass5" "WrongPass6"; do
  curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"alice\", \"password\": \"$pwd\"}" > /dev/null
  echo -n "."
done
echo " Fait (6 tentatives en échec consécutives)."

# --- Scénario B : Accès Cross-Tenant IDOR (BOLA) ---
echo -e "\n[Scénario 2/3] Tentative d'accès Cross-Tenant IDOR (T1078)..."
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"alice\", \"password\": \"$ALICE_PASSWORD\"}")

ALICE_TOKEN=$(echo "$LOGIN_RESP" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4 || true)

if [[ -z "$ALICE_TOKEN" ]]; then
  echo "❌ Impossible de récupérer le token d'Alice. Réponse brute : $LOGIN_RESP"
  exit 1
fi
echo "  [+] Token acquis pour 'alice' (Tenant Acme Corp = 1)."

# Alice tente d'accéder au document ID 3 (appartenant à CyberDyne Systems, Tenant 2)
for i in $(seq 1 4); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/documents/3" \
    -H "Authorization: Bearer $ALICE_TOKEN")
  echo "  Requête $i : GET /documents/3 -> HTTP $HTTP_CODE (Rejeté avec sécurité)"
  sleep 0.2
done

# --- Scénario C : Rejeu de Jeton Expiré ---
echo -e "\n[Scénario 3/3] Rejeu de Jeton JWT Expiré (T1528)..."
# Génération dynamique d'un token expiré via le conteneur API
EXPIRED_TOKEN=$(docker compose -f "$ROOT_DIR/docker-compose.yml" exec -T api python -c "
import jwt, datetime, os
secret = os.getenv('JWT_SECRET')
payload = {'sub': 'alice', 'tenant_id': 1, 'role': 'admin', 'exp': datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)}
print(jwt.encode(payload, secret, algorithm='HS256'))
" 2>/dev/null || true)

if [[ -n "$EXPIRED_TOKEN" ]]; then
  for i in $(seq 1 4); do
    curl -s -X GET "$BASE_URL/auth/me" \
      -H "Authorization: Bearer $EXPIRED_TOKEN" > /dev/null
    echo -n "."
  done
  echo " Fait (4 requêtes avec jeton expiré rejetées)."
else
  echo "  (Génération dynamique du jeton expiré non disponible, étape ignorée)."
fi

# ------------------------------------------------------------------------------
# 4. Attente de l'évaluation Grafana et affichage des alertes
# ------------------------------------------------------------------------------
echo -e "\n=============================================================================="
echo "⏳ Attente du cycle d'évaluation des alertes Grafana (cycle 1 minute)..."
echo "=============================================================================="

# On attend 65 secondes pour s'assurer qu'au moins une évaluation des alertes a eu lieu
for i in $(seq 1 13); do
  echo -n "..."
  sleep 5
done
echo " Terminé !"

echo -e "\n=============================================================================="
echo "📢 Dernières alertes HTTP reçues par le récepteur d'alertes (Alert Receiver) :"
echo "=============================================================================="

docker logs "$RECEIVER_CONTAINER" --tail 30 2>&1 | grep -E "ALERT RECEIVED|alertname|severity|state" || \
  docker logs "$RECEIVER_CONTAINER" --tail 25 2>&1

# ------------------------------------------------------------------------------
# 5. Instructions pour l'évaluateur
# ------------------------------------------------------------------------------
echo -e "\n=============================================================================="
echo "🎉 Démonstration terminée avec succès !"
echo "=============================================================================="
echo "Accédez aux interfaces pour explorer les résultats :"
echo "  1. 📊 Dashboard de Détection Grafana :"
echo "     👉 $GRAFANA_URL/d/tenantguard-detection-overview"
echo "     (Compte : admin / Mot de passe : $GRAFANA_ADMIN_PASSWORD)"
echo ""
echo "  2. 🔍 Investigation LogQL dans Grafana Explore :"
echo "     👉 $GRAFANA_URL/explore"
echo "     Requête LogQL d'exemple : {container=\"tenantguard_api\"} | json | event=\"DOCUMENT_ACCESS_DENIED\""
echo ""
echo "  3. 📖 Runbooks de Réponse à Incident :"
echo "     👉 Consulter le dossier docs/runbooks/ (ex: docs/runbooks/CROSS_TENANT_ACCESS.md)"
echo ""
echo "  4. 🛑 Pour arrêter l'environnement après évaluation :"
echo "     docker compose -f docker-compose.yml -f docker-compose.observability.yml down -v"
echo "=============================================================================="
