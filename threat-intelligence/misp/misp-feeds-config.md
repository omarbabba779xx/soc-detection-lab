# SocForge — Configuration MISP Feeds

**VM05-MISP**: 10.10.10.22
**Version**: MISP 2.4.x

---

## Feeds OSINT activés

| Feed                  | URL                                              | Format  | Fréquence  | Activé |
|-----------------------|--------------------------------------------------|---------|------------|--------|
| CIRCL OSINT           | https://www.circl.lu/doc/misp/feed-osint/        | MISP    | 1h         | ✅     |
| Botvrij.eu            | https://www.botvrij.eu/data/feed-osint/          | MISP    | 1h         | ✅     |
| abuse.ch URLhaus      | https://urlhaus.abuse.ch/downloads/misp/         | MISP    | 30min      | ✅     |
| abuse.ch MalwareBazaar| https://bazaar.abuse.ch/export/misp/             | MISP    | 1h         | ✅     |
| ESET                  | https://github.com/eset/malware-ioc/             | CSV     | 24h        | ⚠️ Manuel |
| PhishTank             | https://data.phishtank.com/data/online-valid.json| JSON    | 1h         | ⚠️ Clé API requise |

---

## Tags utilisés dans SocForge

| Tag                    | Signification                                  |
|------------------------|------------------------------------------------|
| `tlp:red`              | Partage interne uniquement                     |
| `tlp:amber`            | Partage limité partenaires                     |
| `tlp:green`            | Partage communauté                             |
| `tlp:white`            | Public                                         |
| `socforge:lab`         | IOC généré dans le lab SocForge               |
| `socforge:purple-team` | Artefact d'exercice Purple Team               |
| `mitre-attack:t1059.001` | Technique MITRE associée                    |
| `type:ip-src`          | IP source malveillante                         |
| `type:domain`          | Domaine malveillant                            |

---

## Événements MISP créés manuellement

### MISP Event #2108 — Purple Team Exercise IOCs
- **Date**: 2026-08-07
- **Distribution**: Your Organisation Only
- **Threat level**: Low (exercice contrôlé)
- **Attributs**:
  - `ip-src | 10.10.10.60` — VM12-PURPLE (attaquant lab)
  - `hostname | dc01.socforge.lab` — cible DC01
  - `hostname | win01.socforge.lab` — cible WIN01
  - Tag: `socforge:purple-team`, `tlp:red`

---

## Intégration Cortex → MISP

Cortex analyzer `MISP_2_0` configuré avec:
- URL: `http://10.10.10.22`
- API Key: (stockée dans `secrets/lab-registry.md`)
- Verifyssl: false (lab self-signed)

Requête type depuis Shuffle:
```json
POST http://10.10.10.22/attributes/restSearch
Authorization: <MISP_API_KEY>
{
  "value": "10.10.10.60",
  "type": ["ip-src", "ip-dst"],
  "returnFormat": "json"
}
```

---

## Procédure de mise à jour des feeds

```bash
# Sur VM05-MISP
sudo -u www-data php /var/www/MISP/app/Console/cake Admin updateAllFeeds
sudo -u www-data php /var/www/MISP/app/Console/cake Admin cacheFeeds
```
