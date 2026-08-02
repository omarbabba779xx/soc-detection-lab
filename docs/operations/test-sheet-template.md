# Fiche de test — SocForge

## Métadonnées

| Champ | Valeur |
|---|---|
| ID du test | SF-TEST-YYYY-NNN |
| Date | YYYY-MM-DD |
| Analyste | [Prénom] |
| Phase | Phase X |
| Technique ATT&CK | T[ID] — [Nom de la technique] |
| Tactique ATT&CK | [Tactique] |

## Objectif du test

[Décrire ce que le test cherche à valider en 1 à 3 phrases.]

## Comportement à détecter

[Décrire précisément le comportement malveillant simulé.]

## Sources de données attendues

- [ ] Sysmon (EventID : ___)
- [ ] Windows Event Log (EventID : ___)
- [ ] auditd
- [ ] Zeek (log : ___)
- [ ] Suricata (alerte : ___)
- [ ] Firewall log
- [ ] Autre : ___

## Règle censée détecter

| Champ | Valeur |
|---|---|
| ID de la règle | SF-[CAT]-[NUM] |
| Fichier | `wazuh/rules/...` ou `detections/sigma/...` |
| Gravité | Low / Medium / High / Critical |

## Prérequis

- VM à démarrer : ___
- Snapshot pris : ☐ Oui / ☐ Non — Nom : ___
- Services vérifiés actifs : ___

## Scénario d'exécution

### Commande / action exécutée

```bash
# Coller la commande exacte ici
```

### Paramètres personnalisés

[Décrire les valeurs spécifiques utilisées : IP, utilisateur, chemin...]

## Résultats attendus

| Composant | Résultat attendu |
|---|---|
| Événement brut | [Description] |
| Alerte Wazuh | [Description + gravité] |
| Workflow Shuffle | [Déclenché / Non déclenché] |
| Cas TheHive | [Créé / Non créé] |
| Enrichissement | [IOC enrichi / Non enrichi] |

## Résultats observés

| Composant | Résultat observé | Conforme |
|---|---|---|
| Événement brut | | ☐ Oui ☐ Non |
| Alerte Wazuh | | ☐ Oui ☐ Non |
| Workflow Shuffle | | ☐ Oui ☐ Non |
| Cas TheHive | | ☐ Oui ☐ Non |
| Enrichissement | | ☐ Oui ☐ Non |

## Temps mesurés

| Étape | Timestamp | Durée |
|---|---|---|
| Exécution du test | | — |
| Apparition événement brut | | Δ ___ s |
| Alerte Wazuh générée | | Δ ___ s (MTTD) |
| Réception Shuffle | | Δ ___ s |
| Cas TheHive créé | | Δ ___ s (MTTA) |

## Faux positifs connus

[Décrire les cas légitimes qui pourraient déclencher cette règle.]

## Limites

[Décrire les cas où la règle ne détecterait pas le comportement.]

## Captures prises

- [ ] Événement brut dans Wazuh Dashboard
- [ ] Alerte Wazuh
- [ ] Workflow Shuffle déclenché
- [ ] Cas TheHive créé
- [ ] Enrichissement IOC

## Statut final

- [ ] ✅ Test validé — règle fonctionne comme attendu
- [ ] ⚠️ Partiel — voir remarques
- [ ] ❌ Échec — règle à corriger

## Remarques

[Notes libres, problèmes rencontrés, ajustements effectués.]

## Fichiers associés

- Règle : `[chemin dans le dépôt]`
- Capture : `evidence/screenshots/[nom-fichier]`
- Rapport : `reports/test-reports/[nom-fichier]`
