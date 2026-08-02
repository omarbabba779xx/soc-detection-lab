# Rapport d'incident — SocForge

## En-tête

| Champ | Valeur |
|---|---|
| ID incident | INC-YYYY-MM-DD-NNN |
| Titre | [Description courte] |
| Gravité | Low / Medium / High / Critical |
| Statut | New / In Progress / Resolved / Closed |
| Analyste | [Prénom] |
| Date d'ouverture | YYYY-MM-DD HH:MM |
| Date de résolution | YYYY-MM-DD HH:MM |
| MTTD | ___ minutes |
| MTTA | ___ minutes |
| MTTR | ___ minutes |

## Résumé exécutif

[2 à 5 phrases résumant l'incident : que s'est-il passé, sur quelle machine, quelle technique ATT&CK, quel impact, comment résolu.]

## Chronologie

| Timestamp | Événement |
|---|---|
| YYYY-MM-DD HH:MM | Détection de l'alerte Wazuh |
| YYYY-MM-DD HH:MM | Réception par Shuffle |
| YYYY-MM-DD HH:MM | Création du cas TheHive |
| YYYY-MM-DD HH:MM | Début de l'investigation |
| YYYY-MM-DD HH:MM | [Étape clé] |
| YYYY-MM-DD HH:MM | Résolution |

## Détails techniques

### Alerte initiale

- Source : [VM ou service]
- Règle déclenchée : [ID + nom]
- Technique ATT&CK : [T-ID + nom]

### Artefacts identifiés

| Type | Valeur | Contexte |
|---|---|---|
| IP | | |
| Hash | | |
| Fichier | | |
| Utilisateur | | |
| Process | | |

### Enrichissement IOC

| IOC | Source | Résultat |
|---|---|---|
| | VirusTotal | |
| | AbuseIPDB | |
| | MISP | |

## Investigation

### Actions réalisées

1. [Action 1]
2. [Action 2]
3. [...]

### Collecte Velociraptor

- Hunt exécuté : [Oui / Non]
- Artefacts collectés : [Liste]
- Hash SHA-256 des artefacts : [voir chaîne de conservation]

## Réponse

### Actions de remédiation

| Action | Statut | Validée par |
|---|---|---|
| [ex: Blocage IP sur FW] | Effectuée | Analyste |
| [ex: Désactivation compte] | Effectuée | Analyste |

## Conclusion

### Cause racine

[Explication de la cause de l'incident.]

### Impact

[Impact réel ou potentiel dans le lab.]

### Leçons apprises

[Ce qui a bien fonctionné, ce qui doit être amélioré.]

### Règles créées ou modifiées

- [ID règle] : [Description de la modification]

## Annexes

- Captures : `evidence/screenshots/INC-YYYY-MM-DD-NNN/`
- Artefacts : `dfir/artifacts/INC-YYYY-MM-DD-NNN/`
- Chaîne de conservation : `dfir/chain-of-custody/INC-YYYY-MM-DD-NNN.md`
