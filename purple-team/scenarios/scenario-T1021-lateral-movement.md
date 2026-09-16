# Scénario Purple Team — T1021.002 SMB Admin Shares

**ID Scénario**: SC-004
**Technique MITRE**: T1021.002
**Outil**: net use / impacket
**Date test**: 2026-08-07
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: DC01 (10.10.10.109)

---

## Objectif

Valider la détection d'accès aux partages administratifs Windows utilisés pour le mouvement latéral. Vérifier que l'EventID 5140 est bien capturé et la règle 100140 déclenchée.

---

## Pré-requis

- [ ] VM12-PURPLE démarrée
- [ ] DC01 démarrée avec Wazuh Agent + audit object access activé
- [ ] Credentials valides: `Administrator` / `<LAB_PASSWORD>`

---

## Étapes d'exécution (Red Team)

### Test 1 — Connexion share ADMIN$

```bash
# Depuis VM12-PURPLE (Linux)
smbclient //10.10.10.109/ADMIN$ -U 'SOCFORGE\Administrator%<LAB_PASSWORD>'
# ou
impacket-smbclient SOCFORGE/Administrator:<LAB_PASSWORD>@10.10.10.109
```

### Test 2 — Connexion share C$

```bash
impacket-smbclient SOCFORGE/Administrator:<LAB_PASSWORD>@10.10.10.109 -k
# Dans smbclient: use C$
```

### Test 3 — net use (depuis WIN01)

```cmd
# Depuis WIN01 (simuler pivot)
net use \\10.10.10.109\ADMIN$ /user:SOCFORGE\Administrator <LAB_PASSWORD>
dir \\10.10.10.109\ADMIN$
net use \\10.10.10.109\ADMIN$ /delete
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `rule.id: "100140"` → hits immédiats
2. Wazuh Dashboard → `data.win.system.eventID: "5140"` → détail par share
3. TheHive → Alertes → `[Wazuh] Admin share access`
4. Vérifier que l'IP source 10.10.10.60 est bien dans l'observable TheHive

---

## Résultats

| Test   | Détecté | Règle  | MTTD  | Hits      |
|--------|---------|--------|-------|-----------|
| Test 1 | ✅      | 100140 | 23s   | 651,566   |
| Test 3 | ✅      | 100140 | 23s   | (inclus)  |

> **Correctif appliqué (2026-09-14)** : la règle se déclenchait sur chaque accès EventID 5140 correspondant à `ADMIN$`/`C$`, y compris le trafic Windows/GPO légitime en arrière-plan (compte machine `HOSTNAME$`) — d'où les 651 564 déclenchements initiaux. Corrigé dans `wazuh/rules/socforge_sigma_rules.xml` : la règle 100140 exclut désormais les comptes se terminant par `$` (nouvelle règle 100139, niveau 3, capture ce bruit séparément sans alerter). Redéployé sur le manager Wazuh en direct et confirmé sans erreur de chargement.
>
> **Correctif complémentaire (2026-09-16)** : test live sur DC01+WIN01 a révélé un second faux positif réel — le trafic natif Windows (résolution de noms/Netlogon vers `IPC$`) utilise le compte **`ANONYMOUS LOGON`** (SID `S-1-5-7`), qui ne se termine pas par `$` et n'était donc pas filtré par le correctif précédent. 5 faux positifs réels capturés sur le manager avant correctif. Règle 100139/100140 mise à jour : le filtre exclut maintenant `\$$` **OU** `^ANONYMOUS LOGON$` (regex `(?i)(\$$|^ANONYMOUS LOGON$)`). Redéployé en direct sur VM02-WAZUH, vérifié sans erreur de chargement, et logique de filtrage validée explicitement en Python contre l'événement brut capturé (voir `wazuh/rules/socforge_sigma_rules.xml`, règles 100139/100140).
>
> **Preuve — Wazuh Dashboard, requête `rule.id:100139 or rule.id:100140` :**
>
> ![Détail événement ANONYMOUS LOGON](../../docs/screenshots/scenario4-anonymous-logon-fix-1.png)
> ![Liste des hits historiques](../../docs/screenshots/scenario4-anonymous-logon-fix-2.png)
