# Plan d'adressage réseau — SocForge (déployé)

> Ce document reflète le réseau **tel que réellement déployé**.
> Le plan initial prévoyait 6 zones réseau séparées (`mgmt`, `srv`, `ep`, `ndr`, `purple`, `dfir`)
> avec routage inter-zones par VM01-FW. État réel au 2026-09-16 : `dfir`, `srv` et `ep` sont
> déployées et leur routage inter-zone validé en direct ce jour (voir preuves ci-dessous).
> Les zones `purple` (PURPLE) et `ndr` (NDR) ont leurs NICs dédiées déjà présentes et les
> règles firewall OPNsense actives côté VM01-FW (`pfctl -sr` confirme les 5 règles `pass` sur
> em2-em6), mais leur IP/route côté VM n'a pas pu être configurée/testée cette session
> (accès console PURPLE bloqué — identifiants GUI Kali non résolus dans le temps disponible ;
> NDR non tenté) — elles continuent donc à opérer en pratique sur `socforge-mgmt`.

## Preuves — routage inter-zone réel

**Zone srv (DC01)** — testé en direct le 2026-09-16 : `ping` depuis VM01-FW (10.10.20.1,
interface em2/OPT1) vers DC01 (10.10.20.10, adaptateur "Ethernet 2" / réseau interne
`socforge-srv`) → **0% de perte, 3/3 paquets reçus** (RTT 0.88-1.48ms), après ajout d'une
route retour `10.10.10.0/24 via 10.10.20.1` sur DC01. Capture :
[`docs/screenshots/zone-srv-routing-proof.png`](../screenshots/zone-srv-routing-proof.png).

**Zone ep (WIN01 + LINUX01)** — testé en direct le 2026-09-16 : `ping` depuis VM01-FW
(10.10.30.1, interface em3/OPT2) vers WIN01 (10.10.30.110, adaptateur "Ethernet") → **0% de
perte, 3/3 paquets reçus**, après assignation de l'IP statique et ajout d'une règle pare-feu
Windows autorisant ICMPv4 (profil réseau "Public" par défaut bloquant l'écho). Capture :
[`docs/screenshots/zone-ep-routing-proof.png`](../screenshots/zone-ep-routing-proof.png).
Puis vers LINUX01 (10.10.30.20, déjà configuré, `enp0s3`) → **0% de perte, 3/3 paquets reçus**
sans modification supplémentaire. Capture :
[`docs/screenshots/zone-ep-linux01-routing-proof.png`](../screenshots/zone-ep-linux01-routing-proof.png).

## Réseaux VirtualBox (déployés)

| Réseau VirtualBox | Sous-réseau       | Usage                                                   |
|-------------------|-------------------|---------------------------------------------------------|
| socforge-mgmt     | 10.10.10.0/24     | Réseau principal — Wazuh, TheHive, Cortex, MISP, Shuffle, WIN01, LINUX01, PURPLE, NDR (interface mgmt) |
| socforge-srv      | 10.10.20.0/24     | Zone serveurs — DC01 (10.10.20.10), routage validé via VM01-FW (OPT1/em2) |
| socforge-ep       | 10.10.30.0/24     | Zone endpoints — WIN01 (10.10.30.110), LINUX01 (10.10.30.20), routage validé via VM01-FW (OPT2/em3) |
| socforge-ndr      | 10.10.40.0/24 (prévu) | Zone NDR (tap) — NIC présente sur NDR, IP/route non encore configurée |
| socforge-purple   | 10.10.50.0/24 (prévu) | Zone purple team — NIC présente sur PURPLE, IP/route non encore configurée (accès console bloqué) |
| socforge-dfir     | 10.10.60.0/24     | Zone isolée — VM08 Velociraptor        |
| NAT (WAN)         | DHCP hôte         | Accès Internet temporaire (lab only), port-forwards management |

## Adresses IP par VM (réelles)

| Hostname   | IP mgmt       | IP zone dédiée      | Zone réseau réelle |
|------------|---------------|----------------------|---------------------|
| FW         | 10.10.10.1    | .1 sur chaque zone (OPT1-5) | Passerelle/routeur inter-zones |
| WAZUH      | 10.10.10.10   | —                    | socforge-mgmt        |
| THEHIVE    | 10.10.10.20   | —                    | socforge-mgmt        |
| CORTEX     | 10.10.10.21   | —                    | socforge-mgmt        |
| MISP       | 10.10.10.22   | —                    | socforge-mgmt        |
| SHUFFLE    | 10.10.10.30   | —                    | socforge-mgmt        |
| NDR        | 10.10.10.40   | NIC socforge-ndr présente, non configurée | socforge-mgmt (zone ndr non testée) |
| PURPLE     | 10.10.10.60   | NIC socforge-purple présente, non configurée | socforge-mgmt (accès console bloqué cette session) |
| DC01       | 10.10.10.109  | **10.10.20.10 (socforge-srv, validé)** | socforge-srv + mgmt |
| WIN01      | 10.10.10.110  | **10.10.30.110 (socforge-ep, validé)** | socforge-ep + mgmt |
| LINUX01    | 10.10.10.111  | **10.10.30.20 (socforge-ep, validé)** | socforge-ep + mgmt |
| DFIR-HUNT  | —             | 10.10.60.10/24       | socforge-dfir |

## Plan initial vs réalité

Le plan de projet prévoyait à l'origine 6 zones réseau (`mgmt`, `srv`, `ep`, `ndr`, `purple`, `dfir`) avec routage inter-zones par VM01-FW. État réel : `dfir` et `srv` sont déployées et validées (routage `srv` testé en direct le 2026-09-16, voir preuve ci-dessus). Les zones `ep`, `purple` et `ndr` ont leurs interfaces réseau dédiées déjà présentes sur les VMs concernées et les règles de pare-feu correspondantes sont actives sur VM01-FW, mais la configuration IP/route côté VM reste à finaliser — ces 3 rôles continuent en pratique de fonctionner via `socforge-mgmt`, sans que cela affecte leur fonction (détection, purple team, capture réseau).

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
