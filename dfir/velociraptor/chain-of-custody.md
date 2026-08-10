# Chaîne de Custody — Preuves Numériques SocForge

**Incident**: Purple Team Exercise 2026-08-07
**Numéro de dossier**: SOCFORGE-2026-08-07-001

---

## Formulaire de custody

| Champ               | Valeur                                             |
|---------------------|----------------------------------------------------|
| Date de création    | 2026-08-07                                         |
| Dossier             | SOCFORGE-2026-08-07-001                            |
| Investigateur       | SocForge Lab                                       |
| Environnement       | Lab VirtualBox isolé — non connecté à Internet     |
| Classification      | Confidentiel Lab                                   |

---

## Inventaire des preuves

| ID Preuve | Type          | Description                                         | Source VM  | Hash SHA256 | Collecté par     |
|-----------|---------------|-----------------------------------------------------|------------|-------------|------------------|
| E-001     | Screenshot    | T1059-rule100131-rule-details.jpg                  | WIN01      | (voir git)  | Wazuh Dashboard  |
| E-002     | Screenshot    | T1110-rule60122-bruteforce-29hits.jpg              | DC01       | (voir git)  | Wazuh Dashboard  |
| E-003     | Screenshot    | T1110-rule60122-expanded-dc01.jpg                  | DC01       | (voir git)  | Wazuh Dashboard  |
| E-004     | Screenshot    | T1110-rule60122-rule-details.jpg                   | DC01       | (voir git)  | Wazuh Dashboard  |
| E-005     | Screenshot    | T1021-rule100140-adminshare-651k-hits.jpg          | DC01       | (voir git)  | Wazuh Dashboard  |
| E-006     | VQL Output    | Pslist DC01 — 46 processus                         | DC01       | (voir git)  | Velociraptor     |
| E-007     | Export JSON   | test-alert-T1059.json                              | WIN01      | N/A (test)  | Shuffle/TheHive  |
| E-008     | Export JSON   | test-alert-T1110.json                              | DC01       | N/A (test)  | Shuffle/TheHive  |
| E-009     | Export JSON   | test-alert-T1021.json                              | DC01       | N/A (test)  | Shuffle/TheHive  |

---

## Journal de transfert

| Date       | Action            | De                    | Vers             | Signature |
|------------|-------------------|-----------------------|------------------|-----------|
| 2026-08-07 | Collecte initiale | VM02-WAZUH Dashboard  | Git repo SocForge| SocForge  |
| 2026-08-07 | Collecte initiale | VM08-DFIR Velociraptor| Git repo SocForge| SocForge  |
| 2026-08-07 | Archivage         | Git repo main         | GitHub (privé)   | SocForge  |

---

## Intégrité

Tous les fichiers de preuves sont versionnés dans le dépôt Git SocForge.
La commande suivante permet de vérifier l'intégrité via les commits:

```bash
git log --oneline docs/screenshots/
git show <commit-hash>:<filepath> | sha256sum
```

---

## Notes

- Environnement 100% lab isolé — aucune donnée réelle impliquée
- Toutes les IPs sont des adresses privées VirtualBox (10.10.10.0/24)
- Les comptes utilisés (Administrator, PURPLE-USER) sont des comptes de test dédiés
- Aucune malware réel utilisé — uniquement Atomic Red Team (red teaming autorisé)
