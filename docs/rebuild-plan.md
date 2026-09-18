# Plan de reconstruction — 12 VMs, 3 max simultanées

> Document de travail (non destiné aux recruteurs) : trace la séquence d'utilisation des
> 12 VMs prévues dès l'origine du projet, avec leur rôle, et corrige les faiblesses
> identifiées le 2026-09-17 (preuves visuelles dashboard manquantes, VMs jamais utilisées,
> attaques lancées depuis la victime plutôt que depuis Kali).

## Inventaire et rôles

| VM | IP | Rôle | RAM |
|----|----|------|-----|
| VM01-FW | — (OPNsense) | Pare-feu/segmentation réseau | 1024 |
| VM02-WAZUH | 10.10.10.10 | Manager SIEM (permanent) | 5120 |
| VM03-THEHIVE | 10.10.10.20 | Gestion de cas (SOAR) | 2048 |
| VM04-CORTEX | 10.10.10.21 | Analyseurs automatisés (SOAR) | 1536 |
| VM05-MISP | 10.10.10.22 | Threat intel / IOCs | 2048 |
| VM06-SHUFFLE | 10.10.10.30 | Orchestration SOAR | 3072 |
| VM07-NDR | — | Zeek/Suricata (détection réseau) | 3072 |
| VM08-DFIR-HUNT | — | Threat hunting / forensics | 3072 |
| VM09-DC01 | 10.10.10.109 / .50 | Cible Windows Server (victime) | 3072 |
| VM10-WIN01 | — | Cible Windows 11 (victime) | 4096 |
| VM11-LINUX01 | 10.10.10.111 | Cible Linux (victime) | 2048 |
| VM12-PURPLE | — | Kali — **source d'attaque** | 2048 |

## Faiblesses corrigées avant la reprise du planning

1. **Dashboard Wazuh inaccessible** — aucun port-forward vers le 443 de la VM. Corrigé :
   `--natpf2 "wazuh-dash,tcp,127.0.0.1,8443,,443"`. Dashboard accessible sur
   `https://localhost:8443` une fois WAZUH démarrée.
2. **Attaques lancées depuis la console de la victime** (DC01, WIN01) au lieu de PURPLE —
   pas réaliste pour un scénario purple-team. À partir de maintenant : PURPLE est la
   source, la victime est uniquement observée côté logs/Wazuh.
3. **8 VMs sur 12 sans rôle démontré** (FW, THEHIVE, CORTEX, MISP, SHUFFLE, NDR,
   DFIR-HUNT, LINUX01 côté détection). Plan ci-dessous pour couvrir chacune.

## Séquence enchaînée (3 VMs max simultanées)

WAZUH reste allumée en fil rouge (manager permanent, 5 Go) ; on fait tourner au plus 2
autres VMs à côté d'elle.

| Étape | Trio actif | Objectif |
|-------|-----------|----------|
| 1 | WAZUH seule | Vérifier stack complète (manager+indexer+dashboard), capture dashboard des règles déjà prouvées (100153, 100178, 100120/121/131/127) |
| 2 | WAZUH + PURPLE + DC01 | Scan réseau (100101/100102) et brute force (100110/100111) lancés **depuis PURPLE contre DC01** |
| 3 | WAZUH + PURPLE + LINUX01 | sudo abuse (100200) et cron persistence (100210) depuis PURPLE contre LINUX01 |
| 4 | WAZUH + DC01 + WIN01 | Règles restantes nécessitant l'agent local : 100103 (LSASS), 100139/100140 (mouvement latéral DC01↔WIN01), 100147 (registre), 100155 (injection), 100186 (profil PowerShell, re-test) |
| 5 | WAZUH + NDR + PURPLE | Trafic Zeek/Suricata généré par une attaque PURPLE→cible, capture NDR |
| 6 | WAZUH + THEHIVE + CORTEX | Créer un cas depuis une alerte Wazuh, lancer un analyseur Cortex |
| 7 | WAZUH + SHUFFLE + THEHIVE | Workflow SOAR : alerte → cas TheHive → action Shuffle |
| 8 | WAZUH + MISP + DFIR-HUNT | Import IOC MISP, requête de chasse DFIR-HUNT sur un artefact laissé par les tests précédents |
| 9 | WAZUH + FW | Vérifier les règles de segmentation OPNsense (logs de blocage inter-VLAN) |

Chaque étape : démarrer, attendre stabilisation complète (service actif, pas juste port
ouvert), exécuter, capturer la preuve, **éteindre avant l'étape suivante** sauf WAZUH.

## Faiblesses additionnelles trouvées et corrigées en cours de route

4. **PURPLE (Kali) sans SSH exploitable** — `sshd` tournait depuis le boot mais restait
   inaccessible depuis l'hôte. Cause racine : `eth1` (le NIC NAT, nic2) était UP mais
   n'avait jamais reçu de bail DHCP (aucune adresse IP), donc aucune réponse ne pouvait
   partir par cette interface. Corrigé via `nmcli device connect eth1`, avec autoconnect
   activé pour survivre au reboot. Root cause probable : cette VM a été créée/clonée sans
   que le NIC NAT soit inclus dans la configuration réseau initiale (seuls eth0/eth2
   statiques étaient définis dans `/etc/network/interfaces`).
5. **Deux règles NAT dupliquées** sur PURPLE (`ssh`->19022 et `sshtemp`->2244, toutes deux
   vers le port invité 22) — nettoyées, une seule règle `sshpurple`->19023 conservée.
6. **Mot de passe dashboard Wazuh invalide** dans le registre — réinitialisé via
   `wazuh-passwords-tool.sh`, nouvelle valeur documentée dans `secrets/lab-registry.md`.
7. **Sysmon (Sysinternals) jamais installé sur DC01** — installé avec une config réseau-
   inclusive (la config SwiftOnSecurity par défaut exclut trop de trafic pour nos tests).
8. **Deux vrais bugs de règle** trouvés via `wazuh-logtest` : 100103 et 100147
   référençaient des groupes `sysmon_eventN` inexistants (convention réelle :
   `sysmon_event_N` avec underscore pour N≥10 ; séparateur OR = `|`, pas `,`). Corrigés,
   revalidés sans avertissement.
9. **Agent dc01 bloqué en `Pending`** après redémarrage du manager (poignée de main
   incomplète) — corrigé par `Restart-Service WazuhSvc -Force` côté DC01.
10. **Scan FIM WIN01 bloqué à 0% CPU indéfiniment** — root cause : fichiers `.gz`
    orphelins dans `queue\diff\file\`, laissés par des redémarrages forcés antérieurs
    pendant qu'un scan tournait, bloquant tout renommage FIM (`ERROR (1124): File
    exists`). Nettoyé (`queue\diff\file\` + `queue\fim\db\fim.db` supprimés). Aggravé
    par une RAM hôte descendue à ~2 Go libres avec 3 VMs actives.
11. **`wazuh-db` planté sur le manager** (`Unable to connect to socket 'queue/db/wdb'`
    en boucle) — processus zombie malgré `wazuh-control status` l'affichant "running".
    Corrigé par un redémarrage complet du manager (`systemctl restart wazuh-manager`).
12. **Règle 100147 : `if_group` n'a pas fonctionné pour cette règle custom précise**,
    même avec un groupe correctement tagué (confirmé par test A/B contre `if_sid`
    direct) — possiblement lié à l'incident #11. Corrigé en chaînant sur
    `<if_sid>92300</if_sid>` (règle officielle équivalente) plutôt que sur le groupe.
    Voir `detections/windows/detection-sheet-windows.md` pour le détail complet de
    l'investigation.

## Statut

- [x] Faiblesse 1 corrigée (port-forward dashboard)
- [x] Faiblesses 4-9 corrigées (PURPLE SSH/NAT, doublons de règles, mdp dashboard, Sysmon
  manquant, 2 bugs de règle, agent bloqué)
- [x] Étape 1 — captures dashboard des règles déjà prouvées (3 captures, référencées dans detection-sheet-windows.md)
- [x] Étape 2 — scan + brute force depuis PURPLE contre DC01 : 100101/100102/100110/100111
  validées en direct, captures dashboard incluses (voir `scenario-T1046-port-scan.md` et
  `scenario-T1110-brute-force.md`). Bug `<same_source_ip/>` trouvé et corrigé sur 100111.
- [x] Étape 3 — LINUX01 depuis PURPLE : 100200/100210 validées en direct (voir
  `scenario-T1548-T1053-linux.md`). Agent recréé dans un groupe `linux` dédié (était dans
  `default`, config Windows sans effet) ; NIC mgmt et redirection SSH réparés/persistés.
- [~] Étape 4 — DC01/WIN01 : 100140/100147/100178 validées en direct depuis WIN01 (voir
  `scenario-T1021-win01-to-dc01.md` et `detection-sheet-windows.md`). 100147 a nécessité
  trois corrections successives (groupe mal nommé, blocage FIM réel dû à des fichiers
  orphelins, puis la vraie root cause : `if_group` ne déclenchait pas cette règle custom
  précise — corrigé en chaînant sur `if_sid` directement). Au passage, un `wazuh-db`
  planté sur le manager a été diagnostiqué et corrigé (redémarrage complet du service).
  - **100103** : test bénin construit (ouverture de handle LSASS avec droits 0x1010,
    sans lecture mémoire) mais la frappe clavier simulée d'une commande longue
    (811 caractères) s'est arrêtée à mi-chemin sans erreur — limite/bug de
    `VBoxManage keyboardputstring` sur les longues chaînes, pas un problème de règle.
  - **100155** : non retenté pour éviter de reproduire le même échec d'infrastructure ;
    nécessiterait un vecteur de transfert de commande plus fiable qu'un clavier simulé.
- [ ] Étape 5 — NDR
- [ ] Étape 6 — TheHive + Cortex
- [ ] Étape 7 — Shuffle
- [ ] Étape 8 — MISP + DFIR-HUNT
- [ ] Étape 9 — FW
