# SocForge — Configuration Cortex Analyzers

**VM04-CORTEX**: 10.10.10.21:9001
**Version**: Cortex 3.1.7
**Analyzers activés**: 238 disponibles, 6 configurés pour SocForge

---

## Analyzers actifs dans SocForge

### 1. MaxMind_GeoIP_3_0
**Usage**: Géolocalisation des IP sources dans les alertes Wazuh
```json
{
  "name": "MaxMind_GeoIP_3_0",
  "configuration": {
    "path": "/opt/cortex/MaxMind/GeoLite2-City.mmdb"
  }
}
```
**Déclencheur Shuffle**: Sur tout observable `ip` dans TheHive
**Résultat**: Pays, ville, ASN, coordonnées GPS

---

### 2. MISP_2_0
**Usage**: Lookup d'IOCs dans la base MISP locale
```json
{
  "name": "MISP_2_0",
  "configuration": {
    "url": "http://10.10.10.22",
    "key": "MISP_API_KEY",
    "cert_check": false,
    "auto_extract": true
  }
}
```
**Déclencheur Shuffle**: Sur IP, domain, hash

---

### 3. Abuse_Finder_3_0
**Usage**: Identification du contact abuse pour les IPs malveillantes
```json
{
  "name": "Abuse_Finder_3_0",
  "configuration": {}
}
```

---

### 4. FileInfo_8_0
**Usage**: Analyse statique de fichiers (PE, PDF, Office)
```json
{
  "name": "FileInfo_8_0",
  "configuration": {}
}
```

---

### 5. VirusTotal_GetReport_3_1
**Usage**: Réputation de fichiers et URLs (nécessite clé API VT)
```json
{
  "name": "VirusTotal_GetReport_3_1",
  "configuration": {
    "key": "VT_API_KEY_PLACEHOLDER",
    "polling_interval": 60
  }
}
```
**Note lab**: Clé API gratuite (4 req/min) — suffisant pour le lab

---

### 6. Shodan_Host_2_0
**Usage**: Information sur les services exposés d'une IP
```json
{
  "name": "Shodan_Host_2_0",
  "configuration": {
    "key": "SHODAN_API_KEY_PLACEHOLDER"
  }
}
```

---

## Intégration TheHive → Cortex

Dans TheHive (`conf/application.conf`):
```hocon
cortex {
  servers = [
    {
      name = "cortex-socforge"
      url = "http://10.10.10.21:9001"
      auth {
        type = "bearer"
        key = "CORTEX_API_KEY"
      }
    }
  ]
}
```

---

## Procédure d'enrichissement manuel

```bash
# Soumettre un observable directement à Cortex via API
curl -X POST http://10.10.10.21:9001/api/analyzer/MaxMind_GeoIP_3_0/run \
  -H "Authorization: Bearer CORTEX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "10.10.10.60",
    "dataType": "ip",
    "tlp": 2
  }'
```
