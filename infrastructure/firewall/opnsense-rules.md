# SocForge — Règles Firewall OPNsense

**VM01-FW**: OPNsense 24.x — 10.10.10.1
**Interface WAN**: em0 (NAT vers hôte VirtualBox)
**Interface LAN**: em1 (10.10.10.0/24 — Management)

---

## Interfaces configurées

| Interface | Nom       | IP             | Description                          |
|-----------|-----------|----------------|--------------------------------------|
| em0       | WAN       | DHCP (hôte)    | NAT vers internet (lab uniquement)   |
| em1       | LAN       | 10.10.10.1/24  | Zone Management — tous les services  |
| em2       | OPT1      | 10.10.50.1/24  | Zone Purple Team — VM12 isolée       |
| em3       | OPT2      | 10.10.60.1/24  | Zone DFIR — Velociraptor             |

---

## Règles LAN → WAN (Sortant)

| # | Source         | Destination  | Port     | Action | Description                              |
|---|----------------|--------------|----------|--------|------------------------------------------|
| 1 | 10.10.10.0/24  | any          | any      | PASS   | Management → Internet (mises à jour)     |
| 2 | 10.10.60.0/24  | any          | any      | PASS   | DFIR → Internet (téléchargements)        |

## Règles Purple Team (OPT1) — STRICTEMENT ISOLÉ

| # | Source        | Destination        | Port      | Action | Description                            |
|---|---------------|--------------------|-----------|--------|----------------------------------------|
| 1 | 10.10.10.60   | 10.10.10.109       | 445,139   | PASS   | Purple → DC01 (SMB)                    |
| 2 | 10.10.10.60   | 10.10.10.109       | 3389      | PASS   | Purple → DC01 (RDP)                    |
| 3 | 10.10.10.60   | 10.10.10.110       | 445,139   | PASS   | Purple → WIN01 (SMB)                   |
| 4 | 10.10.10.60   | 10.10.10.110       | 3389      | PASS   | Purple → WIN01 (RDP)                   |
| 5 | 10.10.10.60   | !10.10.10.0/24     | any       | BLOCK  | **Interdit: Purple → Internet/externe** |
| 6 | any           | 10.10.10.60        | any       | BLOCK  | Interdit: accès entrant vers Purple    |

## Règles DFIR (OPT2)

| # | Source         | Destination    | Port  | Action | Description                          |
|---|----------------|----------------|-------|--------|--------------------------------------|
| 1 | 10.10.60.10    | 10.10.10.109   | 8000  | PASS   | Velociraptor → DC01 (gRPC)          |
| 2 | 10.10.60.10    | 10.10.10.110   | 8000  | PASS   | Velociraptor → WIN01 (gRPC)         |
| 3 | 10.10.60.10    | 10.10.10.0/24  | any   | PASS   | DFIR → Management                    |

---

## Règles Syslog → Wazuh

OPNsense envoie ses logs firewall vers Wazuh via syslog UDP:

```
System → Settings → Logging → Remote Logging:
  - Server: 10.10.10.10
  - Port: 514
  - Protocol: UDP
  - Facility: local0
  - Loglevel: notice
```

Format: `filterlog` → décodé par `opnsense-fw` decoder dans Wazuh.

---

## NAT — Port Forwarding (accès hôte)

| Port Hôte | Destination          | Description              |
|-----------|----------------------|--------------------------|
| 12443     | 10.10.10.10:443      | Wazuh Dashboard          |
| 19000     | 10.10.10.20:9000     | TheHive                  |
| 19001     | 10.10.10.21:9001     | Cortex                   |
| 18443     | 10.10.10.22:443      | MISP                     |
| 13001     | 10.10.10.30:3001     | Shuffle Webhook          |
| 18889     | 10.10.60.10:8889     | Velociraptor GUI         |
