# Plan d'adressage réseau — SocForge (déployé)

> Ce document reflète le réseau **tel que déployé**, pas le plan initial.
> Le plan initial prévoyait 5 zones isolées ; le déploiement réel utilise un réseau plat
> sur `socforge-mgmt` pour toutes les VMs sauf DFIR.

## Réseau VirtualBox (déployé)

| Réseau VirtualBox | Sous-réseau       | Usage                                      |
|-------------------|-------------------|--------------------------------------------|
| socforge-mgmt     | 10.10.10.0/24     | Tous services SOC + endpoints + red team   |
| socforge-dfir     | 10.10.60.0/24     | VM08-DFIR uniquement                       |
| NAT (WAN)         | DHCP hôte         | VM01-FW — accès Internet temporaire        |

## Adresses IP fixes par VM (réelles)

| Hostname   | Réseau VirtualBox | IP réelle      | Masque | Passerelle  |
|------------|-------------------|----------------|--------|-------------|
| FW         | socforge-mgmt     | 10.10.10.1     | /24    | —           |
| WAZUH      | socforge-mgmt     | 10.10.10.10    | /24    | 10.10.10.1  |
| THEHIVE    | socforge-mgmt     | 10.10.10.20    | /24    | 10.10.10.1  |
| CORTEX     | socforge-mgmt     | 10.10.10.21    | /24    | 10.10.10.1  |
| MISP       | socforge-mgmt     | 10.10.10.22    | /24    | 10.10.10.1  |
| SHUFFLE    | socforge-mgmt     | 10.10.10.30    | /24    | 10.10.10.1  |
| NDR        | socforge-mgmt     | 10.10.10.40    | /24    | 10.10.10.1  |
| PURPLE     | socforge-mgmt     | 10.10.10.60    | /24    | 10.10.10.1  |
| DC01       | socforge-mgmt     | 10.10.10.109   | /24    | 10.10.10.1  |
| WIN01      | socforge-mgmt     | 10.10.10.110   | /24    | 10.10.10.1  |
| LINUX01    | socforge-mgmt     | 10.10.10.111   | /24    | 10.10.10.1  |
| DFIR-HUNT  | socforge-dfir     | 10.10.60.10    | /24    | 10.10.10.1  |

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
