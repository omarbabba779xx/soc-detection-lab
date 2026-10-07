# SC-12 : NDR (Suricata et Zeek), capture et détection d'un scan

Sessions : Reconstruction, étape 5, 2026-09-18 (capture), 2026-09-23 (détection et intégration SIEM)
Attaquant : PURPLE (Kali, 10.10.10.60)

> Adresse de l'attaquant : ce test date d'avant le 24/09/2026, quand PURPLE avait encore une
> patte sur le réseau mgmt (`10.10.10.60`). Depuis, PURPLE n'existe plus que dans sa zone
> filtrée (`10.10.50.10`) : voir SC-16, « Isolement de l'attaquant ».

Cible : WAZUH manager (10.10.10.10)
MITRE : T1046, Network Service Discovery
Objectif : Prouver que VM07-NDR (Zeek + Suricata) capture réellement le trafic
réseau généré par une attaque PURPLE→cible, après correction de deux bugs qui
empêchaient cette VM de fonctionner depuis sa création.

---

## Bug n°1 : Crash noyau au démarrage (jamais démarrée avec succès avant)

Au premier démarrage, la console affichait un crash noyau complet (trace d'appel avec
RIP/registres, `</TASK>`) en boucle sur le test de performance `raid6: avx2x4 xor()`.
Cause : `CPUProfile: host` exposait AVX2 au CPU virtuel, combiné à
`Effective Paravirt. Prov.: KVM` (le noyau Linux invité pensait tourner sous KVM à
l'intérieur de VirtualBox), une combinaison connue pour déclencher ce crash lors de la
sélection de l'algorithme raid6 au boot.

Corrigé :
```
VBoxManage modifyvm SF-VM07-NDR --paravirtprovider legacy
```
Le démarrage s'est ensuite terminé normalement (`ndr login:` atteint).

## Bug n°2 : Interface de capture mal câblée (même famille que les bugs PURPLE/LINUX01)

Suricata (`/etc/suricata/suricata.yaml`) et Zeek (`/opt/zeek/etc/node.cfg`) étaient
tous deux configurés pour écouter sur `enp0s9`, l'interface NAT (`10.0.4.15/24`), qui
ne voit jamais de trafic inter-VM.

Correction faite une première fois vers `enp0s3` (adressée `10.10.10.40/24`, semblant
correspondre au réseau `socforge-mgmt`), mais cette IP était trompeuse :
vérification par MAC address (`ip link show`) a révélé que `enp0s3` correspond en
réalité au NIC1 (réseau `socforge-ndr`, isolé, où aucune autre VM n'est
connectée), tandis que `enp0s8` (`10.10.40.10/24`) correspond au NIC2
(`socforge-mgmt`, le réseau partagé par PURPLE/WAZUH/DC01/WIN01/LINUX01).

Corrigé (deux fois, la bonne interface étant `enp0s8`) :
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

Suricata (`/var/log/suricata/eve.json`, stats après le scan) :
```
"kernel_packets":24, "decoder":{"ipv4":24,"tcp":24}, "tcp":{"sessions":7,"syn":7}
```

Zeek (`/opt/zeek/logs/current/conn.log`), 7 connexions capturées, correspondance
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

## Détection réelle et intégration au SIEM (2026-09-23)

Le 18/09, la NDR capturait le trafic mais ne pouvait rien détecter, et rien ne
remontait dans Wazuh. Trois défauts expliquaient cet état :

1. Aucune signature de détection : `default-rule-path` pointait vers
   `/etc/suricata/rules`, qui ne contenait que les règles d'événements de protocole
   (`decoder-events`, `dns-events`…). Le fichier `suricata.rules` n'existait pas.
   Corrigé avec `suricata-update` (ET Open) et
   `default-rule-path: /var/lib/suricata/rules` : 52 795 règles chargées, 0 en échec.
2. Adresses IP inversées : la carte du réseau mgmt (`enp0s8`, NIC2) portait
   l'adresse de la zone ndr (`10.10.40.10`), et la carte de la zone ndr (`enp0s3`, NIC1)
   portait l'adresse mgmt (`10.10.10.40`). La sonde ne pouvait donc pas joindre Wazuh.
   Corrigé dans `/etc/netplan/01-socforge-zones.yaml` : `enp0s8` = 10.10.10.40,
   `enp0s3` = 10.10.40.10.
3. `HOME_NET` englobait l'attaquant (`10.0.0.0/8` par défaut). Les signatures
   « ET SCAN » (`$EXTERNAL_NET → $HOME_NET`) ne pouvaient pas se déclencher.
   `HOME_NET` = `[10.10.0.0/16,!10.10.50.0/24,!10.10.10.60]` : la zone purple et
   l'adresse mgmt de PURPLE sont considérées comme externes.

Raccordement à Wazuh : agent Wazuh 4.9.2 (même version que le manager, paquet
bloqué en version), ID 009, dans un groupe dédié `ndr`
([`wazuh/agents/agent-ndr.conf`](../../wazuh/agents/agent-ndr.conf) : `eve.json` au
format JSON). Règle SocForge 100400 (niveau 10, T1046), fille de la règle officielle
86601, pour les signatures `ET SCAN` / `GPL SCAN`
([`wazuh/rules/socforge_ndr_rules.xml`](../../wazuh/rules/socforge_ndr_rules.xml)).

Test, 16:12:31 UTC : `nmap -sS -O` depuis PURPLE (10.10.10.60) vers le manager Wazuh.

| Signature Suricata (ET Open) | SID |
|---|---|
| ET SCAN Suspicious inbound to mySQL port 3306 | 2010937 |
| ET SCAN Suspicious inbound to Oracle SQL port 1521 | 2010936 |
| ET SCAN Suspicious inbound to MSSQL port 1433 | 2010935 |
| ET SCAN Suspicious inbound to PostgreSQL port 5432 | 2010939 |
| ET SCAN Potential SSH Scan | 2001219 |
| ET SCAN NMAP OS Detection Probe | 2018489 |

Dans Wazuh : 7 alertes 100400 (niveau 10) à 16:12:33–34 UTC, agent `ndr`, source
10.10.10.60, plus 2 alertes 86601 (ICMP). L'administration de la sonde elle-même a été
vue : installation du paquet (2902/2904) et `sudo` (100200). C'est l'activité
d'administration attendue.

Capture : [`docs/screenshots/wazuh-ndr-suricata-scan.png`](../../docs/screenshots/wazuh-ndr-suricata-scan.png)

## Prise d'écoute de la zone attaquante (24/09)

La sonde écoutait seulement le réseau mgmt, là où PURPLE avait une carte. PURPLE a été
isolé du réseau mgmt (SC-16, « Isolement de l'attaquant ») : son trafic passe désormais
par sa zone `socforge-purple`, que la sonde ne voyait pas. La sonde a reçu une prise
d'écoute passive sur cette zone :

- 4ᵉ carte VirtualBox `socforge-purple`, politique promiscuous `allow-all`, sans
  adresse IP (`enp0s10`, lien actif, rien de joignable) ;
- Suricata écoute les deux interfaces (`--af-packet`, deux entrées, `cluster-id` 98 et 99) ;
- Zeek passe d'un nœud unique à un cluster (logger, manager, proxy) avec deux capteurs,
  `worker-mgmt` (enp0s8) et `worker-purple` (enp0s10).

Configuration versionnée dans [`ndr/`](../../ndr/). Pendant la bascule, l'ancien processus
Zeek standalone restait actif et tenait le port de métriques 9991 : le manager du cluster
plantait au démarrage (« Failed to setup Prometheus endpoint … 0.0.0.0:9991 »). Arrêté,
puis cluster redéployé.

Vérification avec du trafic ordinaire depuis PURPLE (`ping`, ouverture TCP) :

| Outil | Vu sur `enp0s10` |
|---|---|
| Suricata | flux ICMP `10.10.50.10 → 10.10.50.1` ; 3 alertes `2100366 GPL ICMP_INFO PING *NIX` vers `10.10.10.10` |
| Zeek (`worker-purple`) | `10.10.50.10 → 10.10.50.1 icmp`, `10.10.50.10 → 10.10.20.10 tcp S0` (bloqué par OPNsense, sans réponse) |

Après un redémarrage de la sonde (15:07:45), prise d'écoute, Suricata et les cinq
processus Zeek reviennent seuls (`/etc/cron.d/zeek-start`). Suricata met environ 80 s à
charger ses 52 795 signatures avant de capturer (« All AFP capture threads are running »
à 15:09:46) : un premier trafic de test, envoyé à 15:09:21, n'a été vu que par Zeek.
Refait à 15:20:19, Suricata capturé : 3 alertes `2100366` sur `enp0s10`.

Jusqu'à Wazuh : ces alertes arrivent au manager par l'agent de la sonde (groupe
`ndr`, `eve.json`) : règle 86601 à 15:21:34, `in_iface enp0s10`,
`10.10.50.10 → 10.10.10.10`, `GPL ICMP_INFO PING *NIX`. Le manager était éteint au moment
du trafic : l'agent a conservé les événements et les a transmis à la reconnexion.
Capture : [`docs/screenshots/wazuh-ndr-purple-tap-alerts.png`](../../docs/screenshots/wazuh-ndr-purple-tap-alerts.png)

## Ce que la sonde voit, et ce qu'elle ne voit pas

La sonde écoute deux réseaux : le réseau de gestion et la zone attaquant. Depuis le 07/10, les cibles n'ont plus de
carte sur le réseau de gestion ; c'est donc la prise d'écoute de la zone attaquant qui voit partir les attaques de
PURPLE. Le trafic entre les zones srv et ep (par exemple un mouvement latéral de WIN01 vers DC01) ne passe devant
aucune des deux interfaces : il est couvert par les journaux des postes (SC-08) et par le pare-feu (SC-16), pas par
la sonde. Seules les alertes Suricata remontent à Wazuh ; les journaux Zeek restent sur la sonde, pour l'analyse
après coup.

## Résultats

| Critère              | Valeur                                  |
|-----------------------|------------------------------------------|
| VM07-NDR démarre      | oui (après fix paravirt provider)     |
| Capture Suricata      | oui (24 paquets, 7 sessions TCP)       |
| Capture Zeek          | oui (7 lignes conn.log, correspondance exacte) |
| Détection Suricata (signatures) | oui (52 795 règles ET Open, 6 signatures de scan déclenchées) |
| Alerte dans Wazuh     | oui (100400 niveau 10, agent `ndr`, 7 alertes) |
| Zone attaquante couverte après son isolement | oui (prise d'écoute passive, Suricata + Zeek, persistante) |

## Nettoyage

Aucun artefact laissé sur PURPLE ou WAZUH. NDR reste en fonctionnement pour
l'étape suivante si besoin.
