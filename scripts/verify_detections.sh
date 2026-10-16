#!/usr/bin/env bash
# ==============================================================================
# TenantGuard — Script de Vérification des Règles de Détection (Alerting)
# 1. Déclenche la simulation d'attaques
# 2. Attend l'évaluation périodique par le scheduler de Grafana (cycle 1m)
# 3. Interroge l'API Prometheus / Grafana Alerting
# 4. Affiche le tableau récapitulatif: Règle | Attendu | État Obtenu
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_URL="${BASE_URL:-http://localhost:8000}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
GRAFANA_USER="${GRAFANA_ADMIN_USER:-admin}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:?set GRAFANA_ADMIN_PASSWORD in environment}"
ALICE_PASSWORD="${ALICE_PASSWORD:?set ALICE_PASSWORD in environment (see seed accounts table in README.md, e.g. alice123)}"
BOB_PASSWORD="${BOB_PASSWORD:?set BOB_PASSWORD in environment (see seed accounts table in README.md, e.g. bob123)}"
CHARLIE_PASSWORD="${CHARLIE_PASSWORD:?set CHARLIE_PASSWORD in environment (see seed accounts table in README.md, e.g. charlie123)}"
export ALICE_PASSWORD BOB_PASSWORD CHARLIE_PASSWORD GRAFANA_ADMIN_PASSWORD

echo "=============================================================================="
echo "🚀 1. Lancement de la simulation d'attaques..."
echo "=============================================================================="
bash "$SCRIPT_DIR/simulate_attacks.sh"

echo -e "\n=============================================================================="
echo "⏳ 2. Attente de l'évaluation des règles par Grafana (cycle d'évaluation 1m)..."
echo "=============================================================================="

export GRAFANA_URL GRAFANA_USER GRAFANA_ADMIN_PASSWORD PYTHONIOENCODING=utf-8

python - << 'EOF'
import os
import sys
import time
import json
import base64
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

url = os.getenv("GRAFANA_URL", "http://127.0.0.1:3000") + "/api/prometheus/grafana/api/v1/rules"
user = os.getenv("GRAFANA_USER", "admin")
password = os.getenv("GRAFANA_ADMIN_PASSWORD")
if not password:
    raise ValueError("GRAFANA_ADMIN_PASSWORD is not set in environment")
auth_header = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

expected_rules = [
    "BRUTE_FORCE_LOGIN",
    "CREDENTIAL_STUFFING",
    "CROSS_TENANT_ACCESS",
    "UPLOAD_ABUSE",
    "TOKEN_ABUSE",
    "ACCOUNT_TAKEOVER_SUSPECT",
    "EXFILTRATION_VOLUME"
]

max_wait = 75
interval = 5
elapsed = 0
all_firing = False

while elapsed < max_wait:
    req = urllib.request.Request(url, headers={"Authorization": auth_header})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            rule_map = {}
            for group in data.get("data", {}).get("groups", []):
                for rule in group.get("rules", []):
                    name = rule.get("name")
                    totals = rule.get("totals", {})
                    state = rule.get("state", "inactive")
                    if totals.get("alerting", 0) > 0 or state == "firing":
                        rule_map[name] = "Firing"
                    elif totals.get("pending", 0) > 0 or state == "pending":
                        rule_map[name] = "Pending"
                    else:
                        rule_map[name] = "Inactive"
            
            if all(rule_map.get(r) == "Firing" for r in expected_rules):
                all_firing = True
                print(f"\n[+] Toutes les regles sont passees a l'etat Firing ({elapsed}s ecoulees) !")
                break
    except Exception as e:
        pass
    
    time.sleep(interval)
    elapsed += interval
    sys.stdout.write(".")
    sys.stdout.flush()

# Affichage du tableau recapitulatif
print("\n" + "=" * 70)
print("[*] 3. Tableau Recapitulatif de Detection Grafana Unified Alerting")
print("=" * 70)
print("+--------------------------+-----------------+---------------+")
print("| {:<24} | {:<15} | {:<13} |".format("Regle d'Alerte", "Attendu", "Etat Obtenu"))
print("+--------------------------+-----------------+---------------+")

# Recuperation de l'etat final
req = urllib.request.Request(url, headers={"Authorization": auth_header})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())

final_states = {}
for group in data.get("data", {}).get("groups", []):
    for rule in group.get("rules", []):
        name = rule.get("name")
        totals = rule.get("totals", {})
        state = rule.get("state", "inactive")
        if totals.get("alerting", 0) > 0 or state == "firing":
            final_states[name] = "Firing"
        elif totals.get("pending", 0) > 0 or state == "pending":
            final_states[name] = "Pending"
        else:
            final_states[name] = "Inactive"

all_success = True
for rule in expected_rules:
    obtained = final_states.get(rule, "NotFound")
    if obtained != "Firing":
        all_success = False
    print("| {:<24} | {:<15} | {:<13} |".format(rule, "Firing", obtained))

print("+--------------------------+-----------------+---------------+")

if all_success:
    print("\n[+] SUCCES : Les 7 regles de detection ont ete validees a l'etat 'Firing'.")
    sys.exit(0)
else:
    print("\n[-] AVERTISSEMENT : Certaines regles ne sont pas passees a l'etat 'Firing'.")
    sys.exit(1)
EOF
