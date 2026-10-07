# Inventaire du lab SocForge

> État au 2026-10-07, adresses de zone vérifiées sur les machines. Aucun identifiant ici : les comptes, mots de passe et clés API sont
> dans `secrets/` (hors dépôt).

## Réseaux

| Réseau VirtualBox | Rôle | Plage | Passerelle |
|---|---|---|---|
| `socforge-mgmt` | administration hors bande + trafic des outils SOC (agents, API) | 10.10.10.0/24 | - (non routé) |
| `socforge-srv` | zone serveurs | 10.10.20.0/24 | OPNsense 10.10.20.1 |
| `socforge-ep` | zone postes de travail | 10.10.30.0/24 | OPNsense 10.10.30.1 |
| `socforge-ndr` | zone de la sonde NDR | 10.10.40.0/24 | OPNsense 10.10.40.1 |
| `socforge-purple` | zone attaquant | 10.10.50.0/24 | OPNsense 10.10.50.1 |
| `socforge-dfir` | zone DFIR | 10.10.60.0/24 | OPNsense 10.10.60.1 |

Entre les zones, le trafic passe par OPNsense et suit la politique de
`firewall/segmentation-policy.json` (SC-16). Le réseau mgmt n'est pas filtré : c'est le
réseau d'administration du lab. Ni l'attaquant (PURPLE) ni les cibles (DC01, WIN01, LINUX01) n'y
ont de carte : leurs tentatives vers ce réseau passent par OPNsense, qui ne laisse passer que les
ports des agents (Wazuh 1514/1515, Velociraptor 8889) et journalise le reste. Les cibles ont une
route explicite vers `10.10.10.0/24` par la passerelle de leur zone ; les postes joignent aussi la
zone srv pour le domaine.

## Machines

| VM | Rôle | Logiciel | mgmt | Zone | RAM |
|---|---|---|---|---|---|
| VM01-FW | pare-feu, segmentation | OPNsense 24.7 | 10.10.10.1 | passerelle des 5 zones | 1 Go |
| VM02-WAZUH | SIEM (manager, indexer, dashboard) | Wazuh 4.9.2 | 10.10.10.10 | - | 5 Go |
| VM03-THEHIVE | gestion d'incidents | TheHive 5.4.7 | 10.10.10.20 | - | 2 Go |
| VM04-CORTEX | analyseurs | Cortex 3.1.7 | 10.10.10.21 | - | 1,5 Go |
| VM05-MISP | renseignement sur la menace | MISP 2.4.177 | 10.10.10.22 | - | 2 Go |
| VM06-SHUFFLE | orchestration SOAR | Shuffle (Docker) | 10.10.10.30 | - | 4 Go |
| VM07-NDR | détection réseau | Suricata 6.0.4 (ET Open), Zeek | 10.10.10.40 (écoute) | 10.10.40.10 | 3 Go |
| VM08-DFIR-HUNT | chasse et forensique | Velociraptor 0.77.1 | 10.10.10.61 | 10.10.60.10 | 3 Go |
| VM09-DC01 | contrôleur de domaine `socforge.lab` | Windows Server 2022, Sysmon | (aucune carte mgmt) | 10.10.20.10 | 3 Go |
| VM10-WIN01 | poste membre du domaine | Windows 11, Sysmon | (aucune carte mgmt) | 10.10.30.110 | 4 Go |
| VM11-LINUX01 | serveur Linux, agents Wazuh et Velociraptor | Ubuntu | (aucune carte mgmt) | 10.10.30.20 | 2 Go |
| VM12-PURPLE | attaquant | Kali Linux | - (aucune carte mgmt ; administration par NAT) | 10.10.50.10 | 2 Go |

Hôte : 16 Go de RAM ; les VM sont allumées par groupes, selon le scénario (voir
`docs/rebuild-plan.md`).

## Agents et flux de données

| Source | Collecte | Destination |
|---|---|---|
| DC01, WIN01 (groupe `default`) | Security, Sysmon, PowerShell/Operational, Defender, FIM temps réel | Wazuh |
| LINUX01 (groupe `linux`) | journaux système (sudo), FIM temps réel sur les répertoires cron | Wazuh |
| DC01, WIN01, LINUX01 (client Velociraptor) | chasses et ordres d'isolation, port 8889 | Velociraptor |
| NDR (groupe `ndr`) | Suricata `eve.json` ; écoute du réseau mgmt et de la zone purple (prise d'écoute passive) | Wazuh |
| OPNsense | syslog `filterlog` (UDP 514) | Wazuh |
| Wazuh (alertes de niveau ≥ 10) | intégration native `shuffle` (webhook, joignable seulement depuis le manager) | Shuffle → alerte TheHive avec observables → Cortex (via TheHive, compte de service `thehive`) → MISP, dans la même exécution |
| MISP (publication d'un événement) | artefacts serveur Velociraptor (`AutoHunt`, `Sightings`) | chasse automatique sur les postes Windows et Linux, sightings renvoyés à MISP |
| Shuffle (nœud `Quarantine_Host`) | SSH vers VM08, compte `soar` à clé dédiée, une seule commande autorisée | requête VQL envoyée à Velociraptor |
| Shuffle (workflow `SOAR housekeeping`, planifié) | lecture des alertes TheHive, des sightings MISP, de l'alias OPNsense | résultat des chasses écrit sur les alertes, levée des blocages expirés |
| Velociraptor, OPNsense (API) | HTTPS vérifié par la CA du lab (`pki/socforge-lab-ca.crt`) | MISP, OPNsense |

## Heure

Les heures citées dans la documentation sont en UTC. Les captures du tableau de bord Wazuh, de TheHive et de
Shuffle affichent selon le cas l'heure UTC ou l'heure locale de l'hôte (UTC+1) ; la légende le précise quand
elles diffèrent. Les machines Windows (DC01, WIN01) ont leur horloge
virtuelle en UTC (`rtcuseutc`) et le fuseau UTC (corrigé le 01/10) ; les VM Ubuntu utilisent
`systemd-timesyncd` (intervalle maximal de 5 minutes sur THEHIVE, SHUFFLE et WAZUH). Les dérives de plusieurs
minutes par heure observées jusqu'au 23/09 venaient de VirtualBox en mode de repli sur l'hyperviseur Windows
(faiblesse 26 du plan de reconstruction) ; depuis, les VM tournent en AMD-V natif.
