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

### API appelée en TLS vérifié (24/09)

La première version du script désactivait la vérification TLS (`verify=False`), car
OPNsense présentait un certificat auto-signé pour `OPNsense.localdomain`. Désormais :

- la CA du lab (`pki/socforge-lab-ca.crt`) et un certificat `opnsense.socforge.lab`
  (SAN `IP:10.10.10.1`) sont importés par l'API *Trust* d'OPNsense
  (`/api/trust/ca/add/`, `/api/trust/cert/add/`, champs `crt_payload` / `prv_payload`),
  et l'interface web utilise ce certificat ;
- le script vérifie toujours la chaîne avec la CA du lab. Quand le pare-feu est joint par
  une redirection de port (`OPN_URL=https://127.0.0.1:28443`), `OPN_TLS_NAME=10.10.10.1`
  fait contrôler le certificat contre le nom du pare-feu, et non contre l'adresse
  redirigée.

| Test | Résultat |
|---|---|
| `openssl s_client -verify_ip 10.10.10.1` avec la CA | `Verification: OK` |
| même test sans la CA | code 21, refus |
| `apply_policy.py` sans `OPN_TLS_NAME` | `CERTIFICATE_VERIFY_FAILED`, avant toute modification |
| `apply_policy.py` complet | 12 règles `saved`, `filter apply: OK`, `syslog reconfigure: ok` |

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

**Précision (25/09)** : `10.10.30.10`, la cible de ce scan, n'est portée par aucune machine ; WIN01 est en `10.10.30.110` (`docs/lab-registry.md` corrigé). Cette contre-épreuve prouve donc que le pare-feu laisse passer le trafic autorisé (aucun blocage journalisé), pas qu'un hôte répondait. Le 25/09, un ping lancé depuis OPNsense vers `10.10.30.110` aboutit (3 paquets sur 3).

## Isolement de l'attaquant (24/09)

Les VM du SOC et les cibles ont une patte sur le réseau **mgmt** (10.10.10.0/24), le
réseau d'administration hors bande, qui n'est pas filtré par le pare-feu. Jusqu'au 23/09,
PURPLE y avait aussi une adresse (10.10.10.60) : la machine attaquante atteignait
directement le réseau d'administration, sans passer par aucun contrôle. Les scénarios
SC-05, SC-06, SC-07 et SC-12 ont été réalisés ainsi ; chaque fiche le précise.

Correction : PURPLE n'a plus de carte sur le réseau mgmt. Il lui reste deux cartes :

| Carte | Réseau | Rôle |
|---|---|---|
| NAT (SSH `127.0.0.1:19023` sur l'hôte) | hors lab | administration de la VM depuis l'hôte |
| `socforge-purple` | 10.10.50.10/24 | zone de l'attaquant, derrière OPNsense |

Dans Kali, la config du réseau mgmt a été supprimée (`/etc/network/interfaces` et profil
NetworkManager, sauvegardés), et les deux profils restants sont liés à l'**adresse MAC** de
leur carte et non plus à son nom : retirer la carte avait décalé la numérotation
(`eth1` → `eth0`) et donné à chaque carte la config d'une autre. Le réseau
`10.10.10.0/24` est routé par le pare-feu (`via 10.10.50.1`) : une tentative vers le
réseau d'administration n'est plus perdue, elle est bloquée **et journalisée**.

Test (24/09, 14:57 UTC), depuis PURPLE : `ping` puis ouverture de connexion TCP vers le
manager Wazuh `10.10.10.10:1514`.

| Heure | Wazuh | Détail |
|---|---|---|
| 14:57:02-03 | 100301, niveau 8 | ICMP `10.10.50.10 → 10.10.10.10`, `block` |
| 14:57:05-09 | 100301, niveau 8 | TCP `→ 10.10.10.10:1514`, `block` (une alerte par tentative) |
| 14:57:10 | **100302, niveau 12** | tentatives répétées de la zone attaquante |

Côté PURPLE : 0 réponse au `ping`, connexion TCP refusée ; route
`10.10.10.10 via 10.10.50.1 dev eth1`.

## Captures

- [`docs/screenshots/opnsense-segmentation-policy.png`](../../docs/screenshots/opnsense-segmentation-policy.png) — les 12 règles de la politique dans OPNsense
- [`docs/screenshots/wazuh-opnsense-segmentation-blocks.png`](../../docs/screenshots/wazuh-opnsense-segmentation-blocks.png) — les blocages dans Wazuh, dont 100302 (niveau 12)
- [`docs/screenshots/wazuh-purple-to-mgmt-blocked.png`](../../docs/screenshots/wazuh-purple-to-mgmt-blocked.png) — PURPLE isolé : ses tentatives vers le réseau mgmt bloquées par OPNsense et vues par Wazuh (8 alertes, dont 100302)

## Résultats

| Critère | Valeur |
|---|---|
| Politique de segmentation par zone, par défaut en refus | ✅ (12 règles, alias, versionnée) |
| Blocages envoyés à Wazuh | ✅ (syslog `filterlog`, décodeur `pf`) |
| Tentative de l'attaquant vers une zone interdite détectée | ✅ (100301 par port, 100302 niveau 12) |
| Trafic autorisé non bloqué | ✅ (contre-épreuve zone ep : 0 blocage) |
| Attaquant sans accès au réseau d'administration | ✅ (plus de carte mgmt ; tentatives bloquées et journalisées, 100302) |
