# Plan d'adressage réseau — SocForge (déployé)

> Ce document reflète le réseau **tel que réellement déployé**, pas le plan initial.
> Le plan initial prévoyait 5 zones réseau séparées avec une NIC dédiée par VM
> (voir note ci-dessous) — **cette segmentation n'a jamais été déployée**.
> Le réseau réel est plat : toutes les VMs (sauf DFIR-HUNT) partagent
> `socforge-mgmt`, l'isolation Purple Team étant assurée par des règles
> firewall sur ce même réseau plat plutôt que par une zone dédiée.
> Voir [`infrastructure/firewall/opnsense-rules.md`](../../infrastructure/firewall/opnsense-rules.md)
> pour la confirmation de cet état réel.

## Réseaux VirtualBox (déployés)

| Réseau VirtualBox | Sous-réseau       | Usage                                                   |
|-------------------|-------------------|---------------------------------------------------------|
| socforge-mgmt     | 10.10.10.0/24     | Réseau plat — Wazuh, TheHive, Cortex, MISP, Shuffle, NDR, DC01, WIN01, LINUX01, PURPLE |
| socforge-dfir     | 10.10.60.0/24     | Seule zone réellement isolée — VM08 Velociraptor        |
| NAT (WAN)         | DHCP hôte         | Accès Internet temporaire (lab only), port-forwards management |

## Adresses IP par VM (réelles)

| Hostname   | IP (socforge-mgmt) | Zone réseau réelle |
|------------|---------------------|---------------------|
| FW         | 10.10.10.1          | Passerelle/routeur (NICs supplémentaires configurées mais zones non peuplées) |
| WAZUH      | 10.10.10.10         | socforge-mgmt        |
| THEHIVE    | 10.10.10.20         | socforge-mgmt        |
| CORTEX     | 10.10.10.21         | socforge-mgmt        |
| MISP       | 10.10.10.22         | socforge-mgmt        |
| SHUFFLE    | 10.10.10.30         | socforge-mgmt        |
| NDR        | 10.10.10.40         | socforge-mgmt        |
| PURPLE     | 10.10.10.60         | socforge-mgmt (isolation par règles firewall, pas par zone dédiée) |
| DC01       | 10.10.10.109        | socforge-mgmt        |
| WIN01      | 10.10.10.110        | socforge-mgmt        |
| LINUX01    | 10.10.10.111        | socforge-mgmt        |
| DFIR-HUNT  | —                   | socforge-dfir — 10.10.60.10/24 |

## Plan initial vs réalité

Le plan de projet prévoyait à l'origine 6 zones réseau (`mgmt`, `srv`, `ep`, `ndr`, `purple`, `dfir`) avec routage inter-zones par VM01-FW. En pratique, seule la zone `dfir` a été effectivement séparée — les 5 autres rôles (serveurs, endpoints, NDR, purple team, management) partagent le même réseau plat `socforge-mgmt`. L'isolation du Purple Team (empêcher PURPLE d'atteindre l'extérieur ou d'autres services que ses cibles autorisées) est assurée par des règles firewall explicites sur ce réseau plat plutôt que par une séparation physique de zone.

## Règles de flux inter-VMs (via VM01-FW)

| Source          | Destination          | Ports autorisés    | Justification                    |
|-----------------|-----------------------|--------------------|----------------------------------|
| Toutes VMs      | WAZUH (10.10.10.10)  | TCP 1514, 1515     | Agents Wazuh                     |
| WAZUH           | SHUFFLE (10.10.10.30)| TCP 3001           | Webhooks alertes                 |
| SHUFFLE         | THEHIVE (10.10.10.20)| TCP 9000           | Création de cas                  |
| SHUFFLE         | CORTEX (10.10.10.21) | TCP 9001           | Enrichissement IOC               |
| SHUFFLE         | MISP (10.10.10.22)   | TCP 443            | Lookup IOC                       |
| DFIR-HUNT       | DC01, WIN01          | TCP 8000           | Velociraptor gRPC                |
| PURPLE          | DC01, WIN01          | TCP 445, 3389, ICMP| Tests autorisés uniquement (règle firewall, pas zone dédiée) |
| PURPLE          | !10.10.10.0/24       | any                 | BLOQUÉ — isolation red team      |
| Toutes VMs      | Internet             | BLOQUÉ (sauf mgmt/dfir pour mises à jour) | Isolation lab |

## DNS du laboratoire

- Serveur DNS : DC01 (10.10.10.109) pour le domaine `socforge.lab`
- Domaine AD : `socforge.lab`

## NTP

- Source NTP : `pool.ntp.org` via VM01-FW uniquement
- Fuseau horaire : `Europe/Paris` (UTC+1/+2)
