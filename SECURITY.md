# SECURITY.md — SocForge Lab Policy

## Périmètre autorisé

Ce laboratoire est un environnement **strictement local et isolé**.
Tous les tests sont effectués uniquement contre les VM du laboratoire,
avec des cibles contrôlées et explicitement autorisées.

## Règles absolues

| Règle | Statut |
|---|---|
| Tests uniquement contre les VM du lab | ✅ Obligatoire |
| Aucun malware réel stocké dans ce dépôt | ✅ Obligatoire |
| Aucune donnée personnelle réelle | ✅ Obligatoire |
| Fichiers .env et secrets exclus via .gitignore | ✅ Obligatoire |
| Clés API stockées localement uniquement | ✅ Obligatoire |
| Mode Bridge interdit pour les tests Purple Team | ✅ Obligatoire |
| Snapshot avant chaque campagne de test | ✅ Obligatoire |
| Validation humaine avant toute réponse automatique | ✅ Obligatoire |

## Ce que ce dépôt contient

- Configurations d'outils SOC (Wazuh, Suricata, Zeek, Sigma, YARA)
- Workflows SOAR (Shuffle)
- Templates de cas (TheHive)
- Notebooks de threat hunting
- Scénarios Purple Team non destructifs
- Documentation et rapports anonymisés

## Ce que ce dépôt ne contient jamais

- Mots de passe ou tokens d'accès
- Clés API ou certificats privés
- Malware, exploits ou payloads réels
- Données personnelles ou identifiants réels
- Captures réseau contenant des données sensibles
- Adresses IP publiques de systèmes tiers

## Outils d'émulation utilisés

- **Atomic Red Team** : tests ATT&CK non destructifs
- **MITRE Caldera** : orchestration Purple Team en lab isolé
- **Fichier EICAR** : test antivirus standard, inoffensif
- **Trafic synthétique** : généré localement, sans cible externe

## Signalement

Ce dépôt est un projet éducatif de portfolio.
Pour toute question : ouvrir une issue GitHub.
