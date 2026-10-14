# Runbook d'Incident : EXFILTRATION_VOLUME

## 1. Description & Contexte
Ce runbook régit les alertes consécutives à un volume massif et anormal d'opérations de lecture ou de téléchargement de documents (`DOCUMENT_VIEW` ou `DOCUMENT_DOWNLOAD`) par un utilisateur unique dans un laps de temps resserré. Ce comportement suggère une exfiltration massive de données confidentielles d'un tenant, un moissonnage automatique par script (*scraping*), ou l'action d'un initié malveillant (*malicious insider*).

- **Sévérité :** Medium
- **Tactique MITRE ATT&CK :** Exfiltration / Collection
- **Techniques MITRE ATT&CK :** [T1530 - Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/) / [T1119 - Automated Collection](https://attack.mitre.org/techniques/T1119/)

---

## 2. Déclencheur & Seuil
- **Expression LogQL d'évaluation :**
  ```logql
  sum by (user_id) (count_over_time({container="tenantguard_api"} | json | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW" [5m]))
  ```
- **Seuil d'alerte :** $\ge 20$ événements de consultation ou téléchargement de documents en 5 minutes pour un même `user_id`.
- **Délai d'évaluation :** 1 minute (for: 0s).

---

## 3. Procédure de Triage en Étapes Numérotées

### Étape 1 : Quantifier le volume total et la cadence d'accès
Calculer le nombre exact d'accès réalisés durant la période de pointe :
```logql
sum by (user_id, event) (count_over_time({container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW" [15m]))
```

### Étape 2 : Dresser l'inventaire précis des documents accédés
Identifier chaque document consulté ou téléchargé :
```logql
sum by (document_id, event) (count_over_time({container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW" [15m]))
```
Récupérer les métadonnées et la criticité de ces documents dans PostgreSQL :
```bash
# [Non testée] Extraction des métadonnées des documents touchés
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "SELECT id, filename, tenant_id, file_path, created_at FROM documents WHERE id IN (<LISTE_DOC_IDS>);"
```

### Étape 3 : Vérifier l'existence d'autres canaux d'exfiltration (RAG)
Vérifier si l'utilisateur a également formulé des requêtes d'extraction sémantique RAG pour condenser de l'information confidentielle :
```logql
{container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event="RAG_QUERY"
```

---

## 4. Critères de Faux Positif
1. **Opération de sauvegarde ou archivage légitime :** Un administrateur de tenant procédant à un export global de ses archives documentaires annuelles.
2. **Synchronisation d'un client lourd :** Un client de synchronisation local réindexant l'intégralité du coffre-fort documentaire.

---

## 5. Décision : Escalade vs Clôture
- **Escalade en P1 (Fuite de Propriété Intellectuelle) :** Si les téléchargements ciblent des données stratégiques sans avertissement préalable de l'administrateur du tenant.
- **Clôture :** Si l'administrateur confirme avoir initié une opération de sauvegarde programmée.

---

## 6. Mesures de Confinement (Containment)

### Action A : Révocation immédiate de la session utilisateur *(Testée)*
Provoquer l'invalidation globale de la session pour stopper net le flux d'exfiltration :
```bash
# [Testée] Invalidation globale par rotation de secret JWT
# 1. Remplacer JWT_SECRET dans .env
# 2. Recréer l'API pour appliquer la variable
docker compose up -d api
```

### Action B : Désactivation administrative du compte en base *(Testée)*
```bash
# [Testée] Suspension du compte utilisateur
docker compose exec -T db psql -U tenantguard -d tenantguard_db -c "UPDATE users SET hashed_password = 'SUSPENDED_' || hashed_password WHERE id = <USER_ID_ALERTE>;"
```

### Action C : Throttling / Blocage IP périmétrique *(Non testée en local)*
```bash
# [Non testée - Infrastructure Linux / WAF]
iptables -A INPUT -s <IP_SOURCE> -j DROP
```

---

## 7. Éradication & Récupération
1. **Éradication :** S'assurer que le script d'extraction est déconnecté et ne reçoit plus que des erreurs HTTP 401.
2. **Récupération :**
   - Transmettre au délégué à la protection des données (DPO) et au responsable légal du tenant l'inventaire complet des fichiers téléchargés.
   - Évaluer la sensibilité des données compromises pour déterminer l'obligation légale de notification aux autorités compétentes (ex: CNIL / RGPD article 33).

---

## 8. Modèle de Communication Client / Tenant
```text
Objet : [Alerte Sécurité] Téléchargement massif de documents détecté sur votre espace

Madame, Monsieur le Délégué à la Protection des Données,

Notre système de supervision de la sécurité a détecté un volume inhabituellement élevé de téléchargements et de consultations de documents au sein de votre tenant.
Compte utilisateur initiateur : <USER_ID> (<USERNAME>)
Adresse IP : <IP_SOURCE>
Période : <DATE_HEURE_DEBUT_UTC> à <DATE_HEURE_FIN_UTC>
Nombre total de documents extraits : <NB_DOCUMENTS>

Liste des fichiers concernés :
<LISTE_DOCUMENTS_EXTRAITS>

Mesures prises :
- Suspension conservatoire de la session du compte concerné.
- Préservation des journaux d'audit pour analyse médico-légale.

Nous vous prions de nous confirmer s'il s'agit d'une opération d'archivage autorisée ou si ce compte doit faire l'objet d'une révocation définitive.

L'équipe Sécurité TenantGuard.
```

---

## 9. Preuves Forensiques à Conserver
- **Rapport d'audit complet de toutes les requêtes de téléchargement de la session :**
  ```bash
  curl -s -G "http://127.0.0.1:3100/loki/api/v1/query_range" \
    --data-urlencode 'query={container="tenantguard_api"} | json | user_id="<USER_ID_ALERTE>" | event =~ "DOCUMENT_DOWNLOAD|DOCUMENT_VIEW|RAG_QUERY"' > evidence_exfiltration_user_<USER_ID>.json
  ```
- **Copie horodatée des métadonnées de la table `documents`.**
