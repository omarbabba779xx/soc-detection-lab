# Scénario Purple Team — T1110 Brute Force

**ID Scénario**: SC-002
**Technique MITRE**: T1110, T1110.001
**Outil**: Hydra
**Date test**: 2026-08-07
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: DC01 (10.10.10.109)

---

## Objectif

Valider que Wazuh détecte une attaque par dictionnaire sur les comptes AD via SMB/NTLM et que le seuil de fréquence (5 tentatives en 60s) est correctement configuré.

---

## Pré-requis

- [ ] VM12-PURPLE démarrée (Kali Linux)
- [ ] DC01 démarrée avec Wazuh Agent actif
- [ ] Hydra installé sur VM12: `sudo apt install hydra`
- [ ] Wordlist: `/usr/share/wordlists/rockyou.txt`
- [ ] DC01 accessible depuis VM12 (network Host-Only ou Internal)

---

## Étapes d'exécution (Red Team)

### Test 1 — Brute Force SMB

```bash
# Depuis VM12-PURPLE
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt smb://10.10.10.109 -t 4
```

### Test 2 — Brute Force RDP (si activé)

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.109
```

### Test 3 — Medusa (alternative)

```bash
medusa -h 10.10.10.109 -u Administrator -P /usr/share/wordlists/common-passwords.txt -M smbnt
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `rule.id: ("60122" OR "100111")` → doit montrer les hits
2. Vérifier le décompte: 29+ événements 4625 sur le compte `Administrator`
3. Vérifier que la règle de fréquence 100111 se déclenche après la 5e tentative
4. TheHive → Alertes → `[Wazuh] Brute force`

---

## Résultats

| Test   | Détecté | Règle  | MTTD    | Hits |
|--------|---------|--------|---------|------|
| Test 1 | ✅      | 100111 | 8 sec   | 29   |

---

## Nettoyage

Aucun nettoyage requis (les tentatives échouées ne laissent pas d'artefacts persistants).
