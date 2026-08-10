# SocForge — Configuration Shuffle SOAR

**VM06-SHUFFLE**: 10.10.10.30
**Interface**: http://10.10.10.30:3001
**Identifiants**: admin / S0cF0rge.Lab2024

---

## Workflow principal: Wazuh → MISP → Cortex → TheHive

### Structure du workflow (5 nœuds)

```
[1] Webhook Wazuh       →  [2] Filtre niveau ≥10  →  [3] Lookup MISP
                                                              ↓
                                          [5] Créer Case TheHive ← [4] Analyser Cortex
```

---

### Nœud 1 — Webhook Wazuh

**Type**: Trigger — Webhook
**Nom**: `wazuh-alert-in`
**URL générée**: `http://10.10.10.30:3001/api/v1/hooks/webhook_socforge_wazuh`
**Authentification**: Aucune (lab isolé)

**Configuration**:
```json
{
  "name": "wazuh-alert-in",
  "type": "Trigger",
  "app_name": "Webhook",
  "parameters": {
    "httpmethod": "POST",
    "schema": {
      "alert_id": "string",
      "rule_id": "string",
      "rule_level": "integer",
      "rule_desc": "string",
      "agent_name": "string",
      "src_ip": "string",
      "mitre_id": "string"
    }
  }
}
```

---

### Nœud 2 — Filtre (niveau ≥ 10)

**Type**: Action — Filter
**Condition**:
```
{{ $exec.rule_level }} >= 10
```

---

### Nœud 3 — Lookup MISP

**Type**: Action — HTTP
**App**: MISP
**URL**: `http://10.10.10.22/attributes/restSearch`

```json
{
  "method": "POST",
  "url": "http://10.10.10.22/attributes/restSearch",
  "headers": {
    "Authorization": "MISP_API_KEY",
    "Accept": "application/json"
  },
  "body": {
    "returnFormat": "json",
    "value": "{{ $exec.src_ip }}",
    "type": "ip-src"
  }
}
```

---

### Nœud 4 — Analyser Cortex

**Type**: Action — HTTP
**URL**: `http://10.10.10.21:9001/api/analyzer/MaxMind_GeoIP_3_0/run`

```json
{
  "method": "POST",
  "url": "http://10.10.10.21:9001/api/analyzer/MaxMind_GeoIP_3_0/run",
  "headers": {
    "Authorization": "Bearer CORTEX_API_KEY",
    "Content-Type": "application/json"
  },
  "body": {
    "data": "{{ $exec.src_ip }}",
    "dataType": "ip",
    "tlp": 2
  }
}
```

---

### Nœud 5 — Créer Case TheHive

**Type**: Action — TheHive
**URL**: `http://10.10.10.20:9000/api/v1/alert`

```json
{
  "method": "POST",
  "url": "http://10.10.10.20:9000/api/v1/alert",
  "headers": {
    "Authorization": "Bearer THEHIVE_API_KEY",
    "Content-Type": "application/json"
  },
  "body": {
    "type": "alert",
    "source": "SocForge-Wazuh",
    "sourceRef": "{{ $exec.alert_id }}",
    "title": "[{{ $exec.rule_id }}] {{ $exec.rule_desc }}",
    "description": "Agent: {{ $exec.agent_name }}\nSrc IP: {{ $exec.src_ip }}\nMITRE: {{ $exec.mitre_id }}\nGeoIP: {{ $node['cortex-geoip'].output.country }}",
    "severity": 2,
    "tags": ["wazuh", "{{ $exec.mitre_id }}", "socforge"],
    "observables": [
      {
        "dataType": "ip",
        "data": "{{ $exec.src_ip }}",
        "tags": ["src", "wazuh"]
      }
    ]
  }
}
```

---

## Variables d'environnement Shuffle

| Variable          | Valeur                          |
|-------------------|---------------------------------|
| MISP_URL          | http://10.10.10.22              |
| MISP_API_KEY      | (clé API MISP — voir secrets/)  |
| CORTEX_URL        | http://10.10.10.21:9001         |
| CORTEX_API_KEY    | (clé API Cortex)                |
| THEHIVE_URL       | http://10.10.10.20:9000         |
| THEHIVE_API_KEY   | (clé API TheHive)               |

---

## Test du workflow

```bash
# Simuler une alerte depuis Wazuh Manager ou l'hôte
curl -X POST http://10.10.10.30:3001/api/v1/hooks/webhook_socforge_wazuh \
  -H "Content-Type: application/json" \
  -d @soar/test-alerts/test-alert-T1059.json
```

**Vérification**: TheHive → Alerts → doit apparaître dans les 10–30 secondes
