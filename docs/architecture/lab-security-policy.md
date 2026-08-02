# Politique de sécurité du laboratoire — SocForge

## 1. Périmètre

Ce document définit les règles de sécurité applicables au laboratoire SocForge.
Le laboratoire est exclusivement local, isolé et destiné à un usage éducatif.

## 2. Isolation réseau

### Règles absolues

- Mode **Bridge interdit** pour tout scénario Purple Team ou test actif
- VM12-PURPLE n'accède qu'aux cibles désignées dans la ZONE 30
- Les consoles d'administration (Wazuh, TheHive, Shuffle, MISP, Velociraptor) ne sont accessibles que depuis la ZONE 10
- L'accès Internet est **temporaire uniquement** pour :
  - Installation et mises à jour d'outils
  - Téléchargement d'ISOs légitimes
  - Enrichissement IOC via API publiques autorisées
- Tout le trafic interzone transite par VM01-FW

### Configuration VirtualBox

- Réseaux de type **Internal Network** uniquement pour les scénarios actifs
- NAT uniquement pour les mises à jour, retiré ensuite
- Aucune interface de type Bridged pendant les tests

## 3. Gestion des secrets

- Tous les mots de passe sont stockés dans `secrets/lab-registry.md` (local uniquement, hors Git)
- Les clés API sont référencées dans `.env` (exclu par .gitignore)
- Aucun secret ne doit apparaître dans les commits Git
- Vérifier `git diff --cached` avant chaque commit

## 4. Gestion des VM et snapshots

- **Snapshot obligatoire** avant toute installation majeure
- **Snapshot obligatoire** avant chaque campagne Purple Team
- Nommage des snapshots : `SNAPSHOT-[PHASE]-[DESCRIPTION]-[DATE]`
- En cas de problème : restaurer le snapshot, ne pas corriger à la main si incertain

## 5. Tests et simulations

- Utiliser uniquement des fichiers EICAR pour les tests antivirus
- Utiliser Atomic Red Team avec les commandes non destructives documentées
- Définir les résultats attendus **avant** d'exécuter un test
- Disposer d'un plan de retour arrière pour chaque scénario
- Ne jamais utiliser de malware réel
- Ne jamais utiliser de données d'identification réelles dans les tests

## 6. Réponse automatique (SOAR)

### Actions autorisées sans validation humaine
- Notification (email, webhook)
- Création d'alerte ou de cas TheHive
- Ajout d'observable
- Interrogation Velociraptor (lecture seule)
- Ajout à une liste de surveillance

### Actions nécessitant une validation humaine obligatoire
- Blocage d'une adresse IP sur le firewall
- Désactivation d'un compte
- Suppression ou quarantaine d'un fichier
- Arrêt d'un service
- Toute action irréversible

## 7. Conservation des preuves

- Hash SHA-256 obligatoire pour tout artefact conservé
- Fiche de chaîne de conservation pour chaque collecte DFIR
- Les originaux ne sont jamais modifiés, l'analyse se fait sur une copie
- Aucune donnée personnelle réelle dans le dépôt GitHub

## 8. Durée de rétention

| Type de données | Durée de rétention | Stockage |
|---|---|---|
| Index Wazuh (événements bruts) | 30 jours | VM02 |
| Alertes Wazuh | 90 jours | VM02 |
| Cas TheHive | Durée du projet | VM03 |
| PCAP lab | Jusqu'à validation | VM07 (hors Git) |
| Artefacts Velociraptor | Jusqu'à analyse | VM08 (hors Git) |
| Preuves GitHub | Durée du projet | Dépôt (anonymisées) |
| Snapshots VirtualBox | 2 snapshots par VM max | Hôte local |
