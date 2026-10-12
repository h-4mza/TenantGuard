# ==============================================================================
# Script de simulation locale du pipeline GitLab CI TenantGuard (v0)
# Exécute séquentiellement les 6 étapes de sécurité dans des conteneurs Docker
# ==============================================================================

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " [TenantGuard] Simulation du Pipeline GitLab CI Local " -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$results = [ordered]@{}

# 1. SAST (Semgrep)
Write-Host "--- [1/6] Étape SAST (Semgrep) ---" -ForegroundColor Yellow
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep ci --config auto
if ($LASTEXITCODE -eq 0) { $results["sast"] = "SUCCÈS (0)" } else { $results["sast"] = "ÉCHEC ($LASTEXITCODE) - Findings bloquants" }

# 2. SCA (pip-audit)
Write-Host "`n--- [2/6] Étape SCA (pip-audit) ---" -ForegroundColor Yellow
docker run --rm -v "${PWD}:/app" -w /app python:3.11-slim sh -c "pip install --no-cache-dir pip-audit > /dev/null 2>&1 && pip-audit -r requirements.txt"
if ($LASTEXITCODE -eq 0) { $results["sca"] = "SUCCÈS (0)" } else { $results["sca"] = "ÉCHEC ($LASTEXITCODE) - CVEs détectées" }

# 3. SECRETS (Gitleaks)
Write-Host "`n--- [3/6] Étape SECRETS (Gitleaks) ---" -ForegroundColor Yellow
docker run --rm -v "${PWD}:/path" zricethezav/gitleaks:latest detect --source="/path" --verbose --redact
if ($LASTEXITCODE -eq 0) { $results["secrets"] = "SUCCÈS (0)" } else { $results["secrets"] = "ÉCHEC ($LASTEXITCODE) - Secrets trouvés" }

# 4. BUILD & CONTAINER SCAN (Docker + Trivy)
Write-Host "`n--- [4/6] Étape BUILD & CONTAINER SCAN (Docker + Trivy) ---" -ForegroundColor Yellow
docker build -t tenantguard-api:latest .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity CRITICAL,HIGH --exit-code 1 tenantguard-api:latest
if ($LASTEXITCODE -eq 0) { $results["build"] = "SUCCÈS (0)" } else { $results["build"] = "ÉCHEC ($LASTEXITCODE) - Vulnérabilités HIGH/CRITICAL" }

# 5. DAST (OWASP ZAP Baseline)
Write-Host "`n--- [5/6] Étape DAST (OWASP ZAP Baseline) ---" -ForegroundColor Yellow
docker compose up -d
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8000
if ($LASTEXITCODE -eq 0) { $results["dast"] = "SUCCÈS (0)" } else { $results["dast"] = "ÉCHEC ($LASTEXITCODE) - Alertes de sécurité DAST" }

# 6. REPORT (Syft SBOM)
Write-Host "`n--- [6/6] Étape REPORT (Syft SBOM) ---" -ForegroundColor Yellow
docker run --rm -v "${PWD}:/src" -w /src anchore/syft:latest dir:. -o spdx-json=sbom.spdx.json
if ($LASTEXITCODE -eq 0) { $results["report"] = "SUCCÈS (0) - sbom.spdx.json généré" } else { $results["report"] = "ÉCHEC ($LASTEXITCODE)" }

# Tableau Récapitulatif
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host " Bilan d'exécution du Pipeline GitLab CI (v0) " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
foreach ($step in $results.Keys) {
    $status = $results[$step]
    $color = if ($status -like "SUCCÈS*") { "Green" } else { "Red" }
    Write-Host ("{0,-10} : {1}" -f $step, $status) -ForegroundColor $color
}
Write-Host "========================================================`n" -ForegroundColor Cyan
