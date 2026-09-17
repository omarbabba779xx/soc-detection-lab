# SC-03 — T1021.002 : Remote Services — SMB/Admin Shares

**Session** : Reconstruction, root cause hérité d'une investigation antérieure (2026-09-14/16)
**MITRE** : T1021.002 — Remote Services: SMB/Windows Admin Shares
**Tactique** : Lateral Movement

---

## Objectif

Détecter l'accès à des partages administratifs (`ADMIN$`, `C$`, `IPC$`) par un compte
réel, en filtrant le bruit généré par le trafic Windows légitime (GPO, Netlogon).

## Root cause investiguée et corrigée (historique)

Le déploiement initial de la règle générait **651 566 faux positifs** : Windows accède
en permanence à `IPC$`/`ADMIN$` via son propre compte machine (`HOSTNAME$`) et via
`ANONYMOUS LOGON` (SID `S-1-5-7`) pour la résolution de nom / Netlogon — trafic
normal, pas une attaque.

**Fix** : séparation en deux règles selon `subjectUserName` :

- **100139** (niveau 3, bruit) : `subjectUserName` correspond à `\$$` (compte machine)
  ou `ANONYMOUS LOGON` — filé, pas d'alerte.
- **100140** (niveau 10, détection réelle) : `subjectUserName` **ne** correspond **pas**
  à ce filtre — c'est ce que ressemble un mouvement latéral réel via identifiants
  volés/abusés.

## Détection Wazuh

| Règle | Niveau | Rôle |
|-------|--------|------|
| 100139 | 3  | Bruit filtré (compte machine / ANONYMOUS LOGON) |
| 100140 | 10 | Alerte réelle (compte réel accédant à un partage admin) |

## Statut de re-validation (reconstruction 2026-09-17)

Règles redéployées à l'identique sur le manager propre — logique de filtrage inchangée
depuis la correction originale. Non re-testé en direct dans cette session (le mécanisme
de filtrage par regex ne dépend d'aucun état VM susceptible d'avoir changé lors du
reset), mais reste à re-valider en direct lors du prochain cycle de test purple-team
avant d'être présenté comme "re-confirmé" plutôt que "hérité".
