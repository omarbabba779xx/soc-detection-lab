# Plan d'adressage réseau — SocForge (déployé)

> Ce document reflète le réseau **tel que déployé**.
> Chaque VM dispose d'une NIC sur `socforge-mgmt` (gestion/monitoring) **et** d'une NIC
> sur sa zone dédiée (segmentation). Le routage inter-zones passe par VM01-FW.

## Réseaux VirtualBox (déployés)

| Réseau VirtualBox | Sous-réseau       | Usage                                                   |
|-------------------|-------------------|---------------------------------------------------------|
| socforge-mgmt     | 10.10.10.0/24     | Management/monitoring — Wazuh agents, SSH admin         |
| socforge-srv      | 10.10.20.0/24     | Zone serveurs — DC01, DNS, AD                           |
| socforge-ep       | 10.10.30.0/24     | Zone endpoints — WIN01, LINUX01                         |
| socforge-ndr      | 10.10.40.0/24     | Zone NDR — Zeek/Suricata                                |
| socforge-purple   | 10.10.50.0/24     | Zone red team — Kali/Atomic Red Team                    |
| socforge-dfir     | 10.10.60.0/24     | Zone DFIR — Velociraptor                                |
| NAT (WAN)         | DHCP hôte         | Accès Internet temporaire (lab only)                    |

## Adresses IP par VM (réelles)

| Hostname   | IP mgmt (socforge-mgmt) | IP zone                        | Zone réseau     |
|------------|-------------------------|--------------------------------|-----------------|
| FW         | 10.10.10.1              | —                              | —               |
| WAZUH      | 10.10.10.10             | —                              | socforge-mgmt   |
| THEHIVE    | 10.10.10.20             | —                              | socforge-mgmt   |
| CORTEX     | 10.10.10.21             | —                              | socforge-mgmt   |
| MISP       | 10.10.10.22             | —                              | socforge-mgmt   |
| SHUFFLE    | 10.10.10.30             | —                              | socforge-mgmt   |
| NDR        | 10.10.10.40             | **10.10.40.10/24**             | socforge-ndr    |
| PURPLE     | 10.10.10.60             | **10.10.50.10/24**             | socforge-purple |
| DC01       | 10.10.10.109            | **10.10.20.10/24**             | socforge-srv    |
| WIN01      | 10.10.10.110            | **10.10.30.10/24**             | socforge-ep     |
| LINUX01    | 10.10.10.111            | **10.10.30.20/24**             | socforge-ep     |
| DFIR-HUNT  | —                       | 10.10.60.10/24                 | socforge-dfir   |

## Règles de flux inter-VMs (via VM01-FW)

| Source          | Destination          | Ports autorisés    | Justification                    |
|-----------------|----------------------|--------------------|----------------------------------|
| Toutes VMs      | WAZUH (10.10.10.10)  | TCP 1514, 1515     | Agents Wazuh                     |
| WAZUH           | SHUFFLE (10.10.10.30)| TCP 3001           | Webhooks alertes                 |
| SHUFFLE         | THEHIVE (10.10.10.20)| TCP 9000           | Création de cas                  |
| SHUFFLE         | CORTEX (10.10.10.21) | TCP 9001           | Enrichissement IOC               |
| SHUFFLE         | MISP (10.10.10.22)   | TCP 443            | Lookup IOC                       |
| DFIR-HUNT       | DC01, WIN01          | TCP 8000           | Velociraptor gRPC                |
| PURPLE          | DC01, WIN01          | TCP 445, 3389, ICMP| Tests autorisés uniquement       |
| PURPLE          | Outils SOC           | BLOQUÉ             | Isolation red team               |
| Toutes VMs      | Internet             | BLOQUÉ             | Isolation lab                    |

## DNS du laboratoire

- Serveur DNS : DC01 (10.10.10.109) pour le domaine `socforge.lab`
- Domaine AD : `socforge.lab`

## NTP

- Source NTP : `pool.ntp.org` via VM01-FW uniquement
- Fuseau horaire : `Europe/Paris` (UTC+1/+2)
