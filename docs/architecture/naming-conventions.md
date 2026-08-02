# Conventions de nommage — SocForge

## Identifiants d'alertes Wazuh

Format : `SF-[CATEGORIE]-[NUMERO]`

| Préfixe | Catégorie | Exemple |
|---|---|---|
| SF-WIN | Windows endpoint | SF-WIN-0001 |
| SF-LIN | Linux endpoint | SF-LIN-0001 |
| SF-NET | Réseau / NDR | SF-NET-0001 |
| SF-FIM | File Integrity Monitoring | SF-FIM-0001 |
| SF-EDR | Détection fichier/processus | SF-EDR-0001 |
| SF-AD | Active Directory | SF-AD-0001 |
| SF-FW | Firewall | SF-FW-0001 |
| SF-SOAR | Actions SOAR | SF-SOAR-0001 |

## Incidents TheHive

Format : `INC-YYYY-MM-DD-NNN`

Exemple : `INC-2025-01-15-001`

## Snapshots VirtualBox

Format : `SNAPSHOT-[PHASE]-[DESCRIPTION]-[DATE]`

Exemples :
- `SNAPSHOT-00-BASE-INSTALL-20250101`
- `SNAPSHOT-01-WAZUH-INSTALLED-20250108`
- `SNAPSHOT-PRE-PURPLE-WIN01-20250201`

## Règles Sigma

Format : `socforge_[plateforme]_[comportement].yml`

Exemples :
- `socforge_windows_bruteforce_auth.yml`
- `socforge_linux_ssh_bruteforce.yml`
- `socforge_network_port_scan.yml`

## Règles YARA

Format : `socforge_[cible]_[type].yar`

Exemples :
- `socforge_eicar_test.yar`
- `socforge_suspicious_script.yar`

## Fichiers de preuves

Format : `[DATE]-[HOSTNAME]-[ARTEFACT]-[HASH_COURT].[EXT]`

Exemple : `20250115-WIN01-prefetch-a3f9b2.zip`

## Comptes de service

Format : `svc-[outil]` ou `api-[outil]`

Exemples : `svc-wazuh`, `api-thehive`, `svc-velociraptor`

## Branches Git

Format : `phase/[numero]-[description]`

Exemples :
- `phase/0-setup`
- `phase/1-log-collection`
- `phase/2-detection-engineering`
