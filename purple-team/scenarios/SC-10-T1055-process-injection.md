# SC-10 : T1055 : Process Injection (CreateRemoteThread)

Session : Reconstruction, étape 4, 2026-09-18
Attaquant : WIN01, console locale (`labuser`, cmd élevé)
Cible : WIN01 (agent Wazuh), processus `notepad.exe` local
MITRE : T1055, Process Injection
Tactique : Defense Evasion / Privilege Escalation

---

## Objectif

Valider la détection Sysmon EventID 8 (CreateRemoteThread) après correction du bug
`if_group` sur la règle 100155 (même root cause que 100147/100103).

## Technique utilisée (bénigne)

Script PowerShell (encodé en Base64, `-EncodedCommand`) :
1. Lance `notepad.exe` comme processus cible.
2. `OpenProcess` sur ce processus avec les droits complets.
3. `CreateRemoteThread` pointant sur `kernel32!Sleep` (adresse résolue via
   `GetProcAddress`), avec un paramètre de 500ms.

Aucun shellcode n'est écrit en mémoire, le thread distant exécute uniquement une
fonction Win32 légitime déjà mappée dans le processus cible (`Sleep`), une technique de
test standard qui déclenche la télémétrie Sysmon sans risque réel.

Résultat console :
```
Target handle: True
Remote thread handle: True
Done
```

## Détection Wazuh

| Règle  | Niveau | Source              | Rôle                                    |
|--------|--------|----------------------|--------------------------------------------|
| 100155 | 13     | Sysmon EventID 8     | CreateRemoteThread vers un autre processus |

Testé en direct le 2026-09-18 :

```
Rule: 100155 (level 13) -> 'Sigma T1055: CreateRemoteThread into another process — possible process injection — C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_...\Notepad\Notepad.exe'
StartFunction: Sleep
```

Capture (dashboard Wazuh, 17 correspondances sur `rule.id:100155`) :
[`docs/screenshots/wazuh-dashboard-rule-100155-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100155-live.png)

## Historique du bug (root cause)

Même famille de bug que 100147 et 100103 : `<if_group>sysmon_event8</if_group>` ne
déclenche jamais cette règle custom sur ce manager. Contrairement à 100103 (qui a pu
chaîner sur une règle officielle équivalente, 92900), aucune règle officielle générique
n'existe pour EventID 8, chacune des règles Wazuh natives (92400-92403) est limitée à
un processus cible précis. Corrigé en chaînant sur `<if_sid>185006</if_sid>`, la règle
de base (niveau 0) qui tague tout événement EventID 8 avec le groupe `sysmon_event8`.

## Résultats

| Critère    | Valeur                       |
|------------|--------------------------------|
| Détecté    | validé OUI                        |
| Règle      | 100155                        |
| Verdict    | VP (vrai positif)              |
| Source     | WIN01 (local)                 |

## Nettoyage

Processus `notepad.exe` cible fermé après le test (aucune persistance créée).
