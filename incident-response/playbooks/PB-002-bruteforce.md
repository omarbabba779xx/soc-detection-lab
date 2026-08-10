# PB-002 — Attaque Brute Force (T1110)

**Déclencheur**: Règle Wazuh 100111 / 60122 (niveau ≥ 10, fréquence ≥ 5 en 60s)
**Priorité**: Moyenne
**SLA MTTD cible**: < 3 minutes

---

## Phase 1 — Triage (0–3 min)

1. Vérifier l'alerte dans Wazuh:
   - Quel compte est ciblé? (`targetUserName`)
   - Quelle IP source? (`ipAddress`)
   - Quel type de logon? (type 3 = réseau, type 10 = RDP)
2. Est-ce que l'IP est dans le périmètre lab (10.10.10.0/24)?
   - Oui → test Purple Team attendu? Vérifier le planning
   - Non → attaque externe → **Escalader**

---

## Phase 2 — Investigation (3–15 min)

1. **Chercher un succès** après les échecs:
   - EventID 4624 avec le même `targetUserName` après les 4625
   - Si succès → compte potentiellement compromis → Phase 3 urgente

2. **Volume et timing**:
   - Combien de tentatives? (Wazuh Threat Hunting → rule.id:60122)
   - Attaque en cours ou terminée?

3. **Identifier l'outil**:
   - NTLM LogonType 3 = Hydra / Medusa / SMBloris
   - Kerberos (4768/4771) = Rubeus / kerbrute

4. **Vérifier la VM source** (si IP interne):
   - Velociraptor → pslist sur la VM 10.10.10.60
   - Sysmon-1 sur WIN01 pour processus réseau actifs

---

## Phase 3 — Confinement

**Si compte compromis**:
1. Désactiver le compte dans AD (Get-ADUser → Disable-ADAccount)
2. Bloquer l'IP source dans OPNsense
3. Révoquer les sessions Kerberos actives (klist purge)

**Si compte non compromis mais attaque active**:
1. Bloquer l'IP source dans OPNsense
2. Activer le verrouillage de compte AD (Account Lockout Policy)

---

## Phase 4 — Rapport

1. Documenter: IP source, compte cible, nombre de tentatives, résultat
2. Mettre à jour le registre FP si test Purple Team non planifié
3. Calculer MTTD depuis première tentative détectée
