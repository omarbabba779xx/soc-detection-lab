# Configuration VirtualBox — SocForge

Généré automatiquement lors de la Phase 0.

## VM créées

| VM | UUID | RAM | CPU | Disque | Réseau principal |
|---|---|---|---|---|---|
| SF-VM01-FW | acd0b7aa-9b76-4d4f-9600-3703950efe95 | 1024 Mo | 1 | 15 Go | NAT + 6x intnet |
| SF-VM02-WAZUH | 888b5ca9-b089-47d8-8710-56805162929b | 5120 Mo | 4 | 100 Go | socforge-mgmt |
| SF-VM03-THEHIVE | 1c5d58e5-5546-4bdc-8eff-2c856a2137ad | 3072 Mo | 2 | 40 Go | socforge-mgmt |
| SF-VM04-CORTEX | 966ff40c-6374-4fa9-b605-97bcbb0dbfa2 | 2048 Mo | 2 | 30 Go | socforge-mgmt |
| SF-VM05-MISP | a4f07506-ecda-418b-a967-94596a2d5e48 | 3072 Mo | 2 | 50 Go | socforge-mgmt |
| SF-VM06-SHUFFLE | 43589914-90a8-42df-b514-2504e348b8f7 | 2048 Mo | 2 | 30 Go | socforge-mgmt |
| SF-VM07-NDR | 81e18242-8955-4726-ab26-f787be10269f | 3072 Mo | 2 | 80 Go | socforge-ndr + mgmt |
| SF-VM08-DFIR-HUNT | 447f6928-359e-4ec6-a52b-2098e6e1b262 | 3072 Mo | 2 | 60 Go | socforge-dfir + mgmt |
| SF-VM09-DC01 | 65bc4b8c-be99-4d7d-8092-2ca855828257 | 3072 Mo | 2 | 50 Go | socforge-srv |
| SF-VM10-WIN01 | 00340b98-006a-4e91-8d9d-303a56ff2b39 | 3072 Mo | 2 | 60 Go | socforge-ep |
| SF-VM11-LINUX01 | 09177ae9-0392-4cfc-ac1b-d465eccd9745 | 2048 Mo | 1 | 30 Go | socforge-ep |
| SF-VM12-PURPLE | 440d2a46-041f-4171-b1c8-793587683d3d | 2048 Mo | 2 | 40 Go | socforge-purple |

> **Note (voir `docs/network/IP-plan.md`)** : la colonne "Réseau principal" reflète les noms de réseaux Internal Network configurés à la création des VMs. État réel : `socforge-srv` (DC01), `socforge-ep` (WIN01/LINUX01), `socforge-ndr` (NDR) et `socforge-dfir` (VM08) sont déployées, avec routage inter-zone via VM01-FW validé en direct le 2026-09-16 pour les quatre. Seule `socforge-purple` (VM12) reste à finaliser côté IP/route VM (accès console bloqué cette session) — PURPLE reste donc joignable via `socforge-mgmt` (10.10.10.0/24) en pratique. Voir `docs/network/IP-plan.md` pour le détail complet ("Plan initial vs réalité").

## Réseaux internes créés automatiquement

Les réseaux VirtualBox de type Internal Network sont créés implicitement
lors du premier démarrage d'une VM qui les référence.

| Nom | Zone | Sous-réseau cible |
|---|---|---|
| socforge-mgmt | ZONE 10 | 10.10.10.0/24 |
| socforge-srv | ZONE 20 | 10.10.20.0/24 |
| socforge-ep | ZONE 30 | 10.10.30.0/24 |
| socforge-ndr | ZONE 40 | 10.10.40.0/24 |
| socforge-purple | ZONE 50 | 10.10.50.0/24 |
| socforge-dfir | ZONE 60 | 10.10.60.0/24 |

## Notes importantes

- **NIC NAT temporaire** : toutes les VM Ubuntu ont une NIC NAT (nic2 ou nic3) ajoutée pour l'installation.
  La désactiver après installation : `VBoxManage modifyvm SF-VM0X-NOM --nic2 none`
- **EFI activé** : VM09-DC01, VM10-WIN01 (requis pour Windows Server 2022 et Windows 11)
- **TPM 2.0** : VM10-WIN01 uniquement (requis pour Windows 11)
- **Mode promiscuous** : à activer sur VM07-NDR (eth0) pour la capture réseau Zeek/Suricata
- **Cortex sert en HTTP, pas HTTPS** : le port 9001 (forward NAT 19001) répond en `http://`, pas `https://` — un `curl -k https://...` échoue silencieusement (timeout côté TLS, Cortex répond "Illegal request... Perhaps this was an HTTPS request sent to an HTTP endpoint" dans ses logs). Toujours tester avec `http://127.0.0.1:19001`, jamais `https://`.
