# SC-12 — Étape 5 : Capture NDR (Zeek/Suricata) d'un scan PURPLE

**Session** : Reconstruction, étape 5 — 2026-09-18
**Attaquant** : PURPLE (Kali, 10.10.10.60)
**Cible** : WAZUH manager (10.10.10.10)
**MITRE** : T1046 — Network Service Discovery
**Objectif** : Prouver que VM07-NDR (Zeek + Suricata) capture réellement le trafic
réseau généré par une attaque PURPLE→cible, après correction de deux bugs qui
empêchaient cette VM de fonctionner depuis sa création.

---

## Bug n°1 — Crash noyau au démarrage (jamais démarrée avec succès avant)

Au premier démarrage, la console affichait un crash noyau complet (trace d'appel avec
RIP/registres, `</TASK>`) en boucle sur le test de performance `raid6: avx2x4 xor()`.
Root cause : `CPUProfile: host` exposait AVX2 au CPU virtuel, combiné à
`Effective Paravirt. Prov.: KVM` (le noyau Linux invité pensait tourner sous KVM à
l'intérieur de VirtualBox) — une combinaison connue pour déclencher ce crash lors de la
sélection de l'algorithme raid6 au boot.

**Corrigé** :
```
VBoxManage modifyvm SF-VM07-NDR --paravirtprovider legacy
```
Le démarrage s'est ensuite terminé normalement (`ndr login:` atteint).

## Bug n°2 — Interface de capture mal câblée (même famille que les bugs PURPLE/LINUX01)

Suricata (`/etc/suricata/suricata.yaml`) et Zeek (`/opt/zeek/etc/node.cfg`) étaient
tous deux configurés pour écouter sur `enp0s9` — l'interface NAT (`10.0.4.15/24`), qui
ne voit jamais de trafic inter-VM.

Correction faite une première fois vers `enp0s3` (adressée `10.10.10.40/24`, semblant
correspondre au réseau `socforge-mgmt`) — **mais cette IP était trompeuse** :
vérification par MAC address (`ip link show`) a révélé que `enp0s3` correspond en
réalité au **NIC1** (réseau `socforge-ndr`, isolé, où aucune autre VM n'est
connectée), tandis que `enp0s8` (`10.10.40.10/24`) correspond au **NIC2**
(`socforge-mgmt`, le réseau partagé par PURPLE/WAZUH/DC01/WIN01/LINUX01).

**Corrigé** (deux fois, la bonne interface étant `enp0s8`) :
- `af-packet: interface: enp0s8` dans `suricata.yaml`
- `interface=enp0s8` dans `node.cfg` (zeekctl)
- `ip link set enp0s8 promisc on` (mode promiscuous côté OS invité)
- `VBoxManage modifyvm SF-VM07-NDR --nicpromisc2 allow-all` (déjà fait avant le
  démarrage, côté hyperviseur)

## Test et preuve de capture

Scan de reconnaissance depuis PURPLE contre le manager Wazuh :
```
nmap -sT -Pn -p 22,80,443,1514,1515,9200,55000 10.10.10.10
```

**Suricata** (`/var/log/suricata/eve.json`, stats après le scan) :
```
"kernel_packets":24, "decoder":{"ipv4":24,"tcp":24}, "tcp":{"sessions":7,"syn":7}
```

**Zeek** (`/opt/zeek/logs/current/conn.log`) — 7 connexions capturées, correspondance
exacte avec les 7 ports scannés :
```
10.10.10.60 -> 10.10.10.10:80    REJ
10.10.10.60 -> 10.10.10.10:22    RSTO
10.10.10.60 -> 10.10.10.10:443   RSTO
10.10.10.60 -> 10.10.10.10:9200  REJ
10.10.10.60 -> 10.10.10.10:1515  RSTO
10.10.10.60 -> 10.10.10.10:55000 RSTO
10.10.10.60 -> 10.10.10.10:1514  RSTO
```

## Résultats

| Critère              | Valeur                                  |
|-----------------------|------------------------------------------|
| VM07-NDR démarre      | ✅ OUI (après fix paravirt provider)     |
| Capture Suricata      | ✅ OUI (24 paquets, 7 sessions TCP)       |
| Capture Zeek          | ✅ OUI (7 lignes conn.log, correspondance exacte) |
| Détection Wazuh liée  | Hors périmètre de cette étape (NDR non encore intégré au pipeline d'alertes Wazuh) |

## Nettoyage

Aucun artefact laissé sur PURPLE ou WAZUH. NDR reste en fonctionnement pour
l'étape suivante si besoin.
