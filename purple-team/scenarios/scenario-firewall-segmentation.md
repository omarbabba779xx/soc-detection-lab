# SC-16 — Étape 9 : Segmentation OPNsense et journaux de blocage dans Wazuh

**Session** : Reconstruction, étape 9 — 2026-09-23
**VM actives** : VM02-WAZUH + VM01-FW (OPNsense 24.7) + VM12-PURPLE
**Attaquant** : PURPLE, zone purple (10.10.50.10)
**MITRE** : T1046 — Network Service Discovery
**Objectif** (plan de reconstruction) : vérifier les règles de segmentation OPNsense
(journaux de blocage entre zones).

---

## Constat de départ : aucune segmentation

| Interface | Zone | Réseau |
|---|---|---|
| LAN (em1) | mgmt — outils SOC | 10.10.10.1/24 |
| OPT1 (em2) | srv — DC01 | 10.10.20.1/24 |
| OPT2 (em3) | ep — WIN01, LINUX01 | 10.10.30.1/24 |
| OPT3 (em4) | ndr | 10.10.40.1/24 |
| OPT4 (em5) | purple — Kali | 10.10.50.1/24 |
| OPT5 (em6) | dfir — Velociraptor | 10.10.60.1/24 |

Chaque interface OPT1 à OPT5 n'avait qu'une règle, « SocForge allow optN to any ». Tout
était autorisé entre les zones, rien n'était journalisé et aucun syslog n'était envoyé.
Il n'y avait donc aucun blocage à « vérifier » : la segmentation a été mise en place.

## Politique appliquée

Définie dans [`firewall/segmentation-policy.json`](../../firewall/segmentation-policy.json)
et appliquée par [`firewall/apply_policy.py`](../../firewall/apply_policy.py) via l'API
OPNsense (Firewall > Automation > Filter). La politique est versionnée, rejouable et
idempotente ; la clé API reste hors du dépôt.

| Zone source | Autorisé | Dernière règle |
|---|---|---|
| srv | → mgmt : `SOC_AGENT_PORTS` (Wazuh 1514/1515, Velociraptor 8889) | blocage journalisé |
| ep | → srv : `AD_PORTS` (DNS, Kerberos, NTP, RPC, LDAP(S), SMB, GC) ; → mgmt : `SOC_AGENT_PORTS` | blocage journalisé |
| ndr, dfir | → mgmt : `SOC_AGENT_PORTS` | blocage journalisé |
| purple | → ep (les cibles de test) | blocage journalisé (srv, mgmt, dfir, ndr, pare-feu) |

Les anciennes règles « allow any » des interfaces OPT sont **désactivées**. La page des
règles montre que les « Rules from Automation » sont évaluées avant elles.

Deux particularités de l'API rencontrées :
- sur cette installation, un corps JSON est ignoré (réponse `failed` sans message de
  validation), alors qu'un envoi en formulaire est accepté ;
- `TCP/UDP` n'est pas une valeur de protocole valide : les règles AD sont scindées en
  une règle TCP et une règle UDP.

## Journaux vers Wazuh

- **OPNsense** : destination syslog `10.10.10.10:514/udp`, programme `filterlog`, format BSD.
- **Wazuh** : écoute syslog UDP 514 limitée à `10.10.10.1`
  ([`wazuh/manager/integration-shuffle.xml`](../../wazuh/manager/integration-shuffle.xml)).
  Décodeur officiel `pf`, commun à pfSense et OPNsense.
- La règle officielle de blocage **87701** porte `<options>no_log</options>` : un blocage
  isolé n'est jamais écrit. Trois règles SocForge
  ([`wazuh/rules/socforge_firewall_rules.xml`](../../wazuh/rules/socforge_firewall_rules.xml)) :

| Règle | Niveau | Rôle |
|---|---|---|
| 100300 | 5 | tout blocage entre zones (fille de 87701) |
| 100301 | 8 | blocage dont la source est la zone purple (T1046) |
| 100302 | 12 | 10 blocages en 60 s depuis la même source : scan à travers les zones (T1046) |

## Préparation de PURPLE

- Carte NAT `eth1` de nouveau sans adresse : le profil « Wired connection 1 » n'était pas
  lié à `eth1`, d'où le retour de la faiblesse n°4. Corrigé durablement avec
  `connection.interface-name eth1`.
- Aucune route vers les autres zones : routes persistantes vers 10.10.20/30/40/60.0/24
  via 10.10.50.1, ajoutées au profil `socforge-purple`.

## Test

**15:56:37 UTC** — `nmap -Pn -sT` depuis 10.10.50.10 vers DC01 dans la zone srv
(10.10.20.10, 10 ports AD et administration), puis vers la zone dfir (10.10.60.10,
4 ports). Tous les ports ressortent `filtered`. DC01 était éteint : `filtered` seul ne
prouverait donc rien. La preuve est dans les journaux du pare-feu :

| Heure (UTC) | Règle | Détail |
|---|---|---|
| 15:56:19 | 100301 ×2 | ICMP vers le pare-feu lui-même (10.10.50.1) bloqué |
| 15:56:38 | 100301 ×9 | 10.10.50.10 → 10.10.20.10 : 22, 53, 88, 135, 139, 389, 445, 3389, 5985 |
| 15:56:38 | **100302** (niveau 12) | 10ᵉ blocage en moins de 60 s (port 636) : scan à travers les zones depuis 10.10.50.10 |
| 15:56:39 | 100301 ×7 | 10.10.50.10 → 10.10.60.10 : 22, 443, 8001, 8889 |

**Contre-épreuve, 15:57:10** : le même scan vers la zone ep (10.10.30.10), autorisée
pour PURPLE, ne produit **aucun** blocage. Le pare-feu laisse passer ce qui est permis et
ne bloque que le reste.

## Limite d'architecture

Toutes les VM ont aussi une patte sur le réseau **mgmt** (10.10.10.0/24), qui sert à
l'administration hors bande. Ce réseau n'est pas filtré par le pare-feu, et PURPLE y a
une adresse (10.10.10.60). Les scénarios SC-05, SC-06 et SC-12 (scan, brute force, NDR)
ont utilisé ce réseau mgmt. La segmentation décrite ici s'applique aux **réseaux de
zone**, là où le test place l'attaquant.

## Captures

- [`docs/screenshots/opnsense-segmentation-policy.png`](../../docs/screenshots/opnsense-segmentation-policy.png) — les 12 règles de la politique dans OPNsense
- [`docs/screenshots/wazuh-opnsense-segmentation-blocks.png`](../../docs/screenshots/wazuh-opnsense-segmentation-blocks.png) — les blocages dans Wazuh, dont 100302 (niveau 12)

## Résultats

| Critère | Valeur |
|---|---|
| Politique de segmentation par zone, par défaut en refus | ✅ (12 règles, alias, versionnée) |
| Blocages envoyés à Wazuh | ✅ (syslog `filterlog`, décodeur `pf`) |
| Tentative de l'attaquant vers une zone interdite détectée | ✅ (100301 par port, 100302 niveau 12) |
| Trafic autorisé non bloqué | ✅ (contre-épreuve zone ep : 0 blocage) |
