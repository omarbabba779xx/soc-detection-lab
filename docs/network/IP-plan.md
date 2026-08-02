# Plan d'adressage réseau — SocForge

## Zones réseau VirtualBox (Internal Networks)

| Zone | Réseau VirtualBox | Sous-réseau | Passerelle (FW) | Usage |
|---|---|---|---|---|
| 10 — Management/SOC | socforge-mgmt | 10.10.10.0/24 | 10.10.10.1 | Consoles admin, SIEM, SOAR |
| 20 — Serveurs | socforge-srv | 10.10.20.0/24 | 10.10.20.1 | DC01, serveurs internes |
| 30 — Endpoints | socforge-ep | 10.10.30.0/24 | 10.10.30.1 | WIN01, LINUX01 |
| 40 — NDR/Capture | socforge-ndr | 10.10.40.0/24 | 10.10.40.1 | Capteurs réseau |
| 50 — Purple Team | socforge-purple | 10.10.50.0/24 | 10.10.50.1 | VM12 isolée |
| 60 — DFIR/Hunt | socforge-dfir | 10.10.60.0/24 | 10.10.60.1 | Velociraptor, Jupyter |

## Adresses IP fixes par VM

| Hostname | Interface | Réseau VirtualBox | IP | Masque | Passerelle |
|---|---|---|---|---|---|
| FW | em0 (WAN) | NAT (accès Internet temporaire) | DHCP | — | — |
| FW | em1 (MGMT) | socforge-mgmt | 10.10.10.1 | /24 | — |
| FW | em2 (SRV) | socforge-srv | 10.10.20.1 | /24 | — |
| FW | em3 (EP) | socforge-ep | 10.10.30.1 | /24 | — |
| FW | em4 (NDR) | socforge-ndr | 10.10.40.1 | /24 | — |
| FW | em5 (PURPLE) | socforge-purple | 10.10.50.1 | /24 | — |
| FW | em6 (DFIR) | socforge-dfir | 10.10.60.1 | /24 | — |
| WAZUH | eth0 | socforge-mgmt | 10.10.10.10 | /24 | 10.10.10.1 |
| THEHIVE | eth0 | socforge-mgmt | 10.10.10.20 | /24 | 10.10.10.1 |
| CORTEX | eth0 | socforge-mgmt | 10.10.10.21 | /24 | 10.10.10.1 |
| MISP | eth0 | socforge-mgmt | 10.10.10.22 | /24 | 10.10.10.1 |
| SHUFFLE | eth0 | socforge-mgmt | 10.10.10.30 | /24 | 10.10.10.1 |
| NDR | eth0 | socforge-ndr | 10.10.40.10 | /24 | 10.10.40.1 |
| DFIR-HUNT | eth0 | socforge-dfir | 10.10.60.10 | /24 | 10.10.60.1 |
| DC01 | Ethernet | socforge-srv | 10.10.20.10 | /24 | 10.10.20.1 |
| WIN01 | Ethernet | socforge-ep | 10.10.30.10 | /24 | 10.10.30.1 |
| LINUX01 | eth0 | socforge-ep | 10.10.30.20 | /24 | 10.10.30.1 |
| PURPLE | eth0 | socforge-purple | 10.10.50.10 | /24 | 10.10.50.1 |

## Règles de flux inter-zones (via VM01-FW)

| Source | Destination | Ports autorisés | Justification |
|---|---|---|---|
| Toutes zones | WAZUH (10.10.10.10) | TCP 1514, 1515, 55000 | Agents Wazuh + API |
| ZONE 10 | THEHIVE (10.10.10.20) | TCP 9000 | Console TheHive |
| ZONE 10 | CORTEX (10.10.10.21) | TCP 9001 | Console Cortex |
| ZONE 10 | MISP (10.10.10.22) | TCP 443 | Console MISP |
| ZONE 10 | SHUFFLE (10.10.10.30) | TCP 3001 | Console Shuffle |
| WAZUH | SHUFFLE | TCP 3001 | Webhooks alertes |
| SHUFFLE | THEHIVE | TCP 9000 | Création de cas |
| SHUFFLE | CORTEX | TCP 9001 | Enrichissement IOC |
| SHUFFLE | MISP | TCP 443 | Lookup IOC |
| DFIR-HUNT | WIN01, LINUX01 | TCP 8000 | Velociraptor clients |
| PURPLE | WIN01, LINUX01 | Restreint + défini | Tests autorisés uniquement |
| PURPLE | ZONE 10, 20, 40, 60 | BLOQUÉ | Isolation Purple Team |
| Toutes zones | Internet | BLOQUÉ (sauf exception) | Isolation lab |

## DNS du laboratoire

- Serveur DNS principal : DC01 (10.10.20.10) pour le domaine `socforge.lab`
- Domaine AD : `socforge.lab`
- Résolution externe : uniquement via FW en cas de besoin temporaire

## NTP

- Source NTP : `pool.ntp.org` via VM01-FW uniquement
- Toutes les VM se synchronisent sur le FW ou directement (accès temporaire)
- Fuseau horaire : `Europe/Paris` (UTC+1/+2)
