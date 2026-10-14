#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://localhost:8000"

echo "=== 1. TEST VERROUILLAGE DU COMPTE ALICE EN BASE ==="
echo "--- a. Tentative de login AVANT verrouillage ---"
curl -i -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "alice", "password": "alice123"}'
echo ""

echo "--- b. Application du verrouillage en base ---"
docker compose exec -T db psql -U tenantguard -d tenantguard_db \
    -c "UPDATE users SET hashed_password = 'DISABLED_' || hashed_password WHERE username = 'alice';"

echo "--- c. Tentative de login APRÈS verrouillage ---"
curl -i -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "alice", "password": "alice123"}'
echo ""

echo "--- d. Logs API filtrés sur AUTH_LOGIN ---"
docker compose logs api | grep "AUTH_LOGIN" | tail -n 10
echo ""

echo "=== 2. TEST ROTATION DU JWT_SECRET ==="
echo "--- a. Acquisition d'un token valide pour bob (attaquant) ---"
BOB_RESP=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "bob", "password": "bob123"}')
BOB_TOKEN=$(echo "$BOB_RESP" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
echo "Token acquis: ${BOB_TOKEN:0:25}..."

echo "--- b. Requête AVANT rotation avec le token de l'attaquant ---"
curl -i -s -X GET "$BASE_URL/documents" \
    -H "Authorization: Bearer $BOB_TOKEN"
echo ""

echo "--- c. Rotation de JWT_SECRET et recréation de l'API ---"
NEW_SECRET=$(openssl rand -hex 32)
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$NEW_SECRET|" .env
docker compose up -d api


# Attente de disponibilité de l'API
until curl -s http://localhost:8000/health > /dev/null; do
    sleep 1
done

echo "--- d. Requête APRÈS rotation avec le même token ---"
curl -i -s -X GET "$BASE_URL/documents" \
    -H "Authorization: Bearer $BOB_TOKEN"
echo ""

echo "--- e. Lignes réelles de docker compose logs api sur cette requête ---"
docker compose logs api --tail 15

