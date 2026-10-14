# Runbook d'Incident : UPLOAD_ABUSE

## 1. Description & Contexte
Ce runbook régit les alertes consécutives au rejet répété de téléversements de fichiers (`UPLOAD_REJECTED`). Ces rejets proviennent du filtrage strict de la plateforme : extension interdite (ex: `.exe`, `.sh`, `.bin`, `.py`), taille excessive (> 10 Mo) ou tentative de traversée de répertoire dans le nom de fichier. Une fréquence élevée traduit une tentative de contournement des contrôles de sécurité ou d'injection de payload hostile.

- **Sévérité :** Medium
- **Tactique MITRE ATT&CK :** Initial Access / Execution
- **Technique MITRE ATT&CK :** [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event="UPLOAD_REJECTED" [10m]))
  ```
- **Seuil d'alerte :** $\ge 3$ téléversements rejetés en 10 minutes pour un même `user_id`.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Identifier l'utilisateur et les motifs de rejet
Extraire les motifs précis consignés dans les logs d'audit :
```logql
{container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event="UPLOAD_REJECTED"
```

### Étape 2 : Inspecter les noms de fichiers et extensions tentées
Analyser si les noms comportent des séquences d'évasion (`../`, double extension, caractères de contrôle) :
```logql
sum by (filename, reason) (count_over_time({container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event="UPLOAD_REJECTED" [15m]))
```

### Étape 3 : Contrôler si un téléversement suspect a finalement réussi
Vérifier si l'utilisateur a réussi à téléverser un fichier valide juste après les rejets :
```logql
{container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event="DOCUMENT_UPLOAD"
```
Si un document a été accepté, vérifier son enregistrement en base et son stockage physique :
```bash
# [Non testée] Inspection du document récemment créé en base
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "SELECT id, filename, file_path, tenant_id, created_at FROM documents WHERE tenant_id = <TENANT_ID> ORDER BY id DESC LIMIT 5;"
```

---

## 4. Critères de Faux Positif
1. **Format bureautique non supporté :** Un utilisateur légitime essaye d'uploader des formats anciens non autorisés (.rtf, .odt, .csv) sans intention malveillante.
2. **Fichier volumineux :** Document PDF valide dépassant le seuil de 10 Mo.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P1 (Suspicion de contournement / RCE) :** Si des scripts ou des exécutables ont été soumis (`.sh`, `.exe`, `.php`, `.jsp`, path traversal `..`).
- **Escalade en P2 (Abus persistant) :** Tentatives répétées sans justification métier.
- **Clôture :** Document d'entreprise valide bloqué pour simple dépassement de quota de taille.

---

## 6. Mesures de Confinement (Containment)

### Action A : Suppression ou quarantaine d'un document suspect *(Non testée)*
Si un fichier téléversé par cet utilisateur présente une anomalie, le supprimer immédiatement de la base et du disque :
```bash
# [Non testée] Suppression du document en base
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "DELETE FROM documents WHERE id = <DOC_ID_SUSPECT>;"
```
Purger également le fichier physique dans le conteneur :
```bash
# [Non testée] Suppression du fichier sur le système de fichiers du conteneur API
docker compose exec -T api rm -f /app/uploads/<NOM_FICHIER_UNIQUE>
```

### Action B : Révocation temporaire du compte en base *(Testée)*
```bash
# [Testée] Suspension du compte utilisateur
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'SUSPENDED_' || hashed_password WHERE id = <USER_ID_ALERTE>;"
```

### Action C : Blocage IP au pare-feu *(Non testée en local)*
```bash
# [Non testée - Environnement de production]
iptables -A INPUT -s <IP_UTILISATEUR> -j DROP
```

---

## 7. Éradication & Récupération
1. **Éradication :** S'assurer qu'aucun artefact n'a été inséré dans le dossier `/app/uploads` ou indexé dans la collection vectorielle ChromaDB.
2. **Récupération :** Rappeler à l'utilisateur ou à son organisation la politique d'extensions acceptées (`.txt`, `.pdf`, `.docx`, `.md`) et la taille maximale (10 Mo).

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Information Sécurité] Rejets répétitifs de documents lors de l'upload

Madame, Monsieur,

Notre système de protection a bloqué plusieurs tentatives de téléversement associées au compte utilisateur <USER_ID> au sein de votre tenant.
Motif(s) relevé(s) : <MOTIF_REJET> (ex: format non autorisé ou dépassement de quota 10 Mo).
Fichiers concernés : <NOMS_FICHIERS>.

Pour des impératifs de sécurité et d'intégrité de notre moteur vectoriel RAG, seuls les fichiers aux extensions .pdf, .docx, .txt et .md d'une taille inférieure à 10 Mo sont autorisés.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Logs de rejets de l'utilisateur :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | event="UPLOAD_REJECTED" | user_id="<USER_ID_ALERTE>"' > evidence_upload_rejected_<USER_ID>.json
  ```
