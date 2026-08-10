# Calculs KPI — SocForge SOC Lab

**Période**: 2026-08-01 → 2026-08-10
**Source**: Wazuh OpenSearch, TheHive, Exercice Purple Team 2026-08-07

---

## 1. MTTD — Mean Time To Detect

### Définition

Temps moyen entre le début de l'activité malveillante et la première alerte Wazuh.

### Calcul par scénario

| Scénario       | Début attaque | Première alerte | MTTD     |
|----------------|---------------|-----------------|----------|
| T1059.001      | 14:23:11      | 14:23:58        | 0m 47s   |
| T1110          | 15:01:44      | 15:02:56        | 1m 12s   |
| T1021.002      | 16:45:02      | 16:45:25        | 0m 23s   |
| T1027          | 14:23:11      | 14:23:58        | 0m 47s   |

**MTTD Moyen** = (47 + 72 + 23 + 47) / 4 = **47.25 secondes**

**Objectif initial**: < 5 minutes → ✅ **ATTEINT** (47s << 5min)

---

## 2. Taux de Détection

### Définition

Proportion de techniques attaquées qui ont été détectées.

### Calcul

| Techniques testées | Techniques détectées | Taux |
|-------------------|---------------------|------|
| 4                 | 4                   | 100% |

**Objectif**: > 80% → ✅ **ATTEINT** (100%)

---

## 3. Taux de Faux Positifs (FPR)

### Définition

Proportion d'alertes déclenchées qui sont des faux positifs.

### Calcul

| Alertes totales | Vrais Positifs | Faux Positifs | FPR  |
|-----------------|----------------|---------------|------|
| 4 (scénarios)   | 4              | 0             | 0%   |
| Règle 100140    | 651,566        | 0 (Purple Team) | 0% |

**FPR Global** = 0 / (4 + 651,566) = **< 0.001%**

**Objectif**: < 5% → ✅ **ATTEINT**

Note: Les alertes sur T1021.002 (651k hits) ne sont pas des FP mais des vrais positifs de l'exercice. Elles sont bruyantes → action corrective: ajouter agrégation.

---

## 4. Coverage MITRE ATT&CK

### Calcul

| Tactiques couvertes | Techniques couvertes | Total techniques lab | Coverage |
|--------------------|---------------------|----------------------|----------|
| 8/10               | 18/23               | 23                   | 78%      |

**Objectif**: > 70% → ✅ **ATTEINT** (78%)

---

## 5. Alertes TheHive

### Volume

| Période         | Alertes créées | Source               |
|-----------------|----------------|----------------------|
| 2026-08-07      | 350+           | Wazuh → Shuffle → TheHive |

**Objectif plan initial**: documenter le pipeline → ✅ **ATTEINT**

---

## 6. Couverture des sources de logs

| Source           | Configurée | Active | Logs reçus |
|------------------|-----------|--------|------------|
| DC01 Security    | ✅        | ✅     | ✅         |
| WIN01 Sysmon     | ✅        | ✅     | ✅         |
| WIN01 Security   | ✅        | ✅     | ✅         |
| LINUX01 auditd   | ✅        | ⚠️ Config  | Planifié   |
| OPNsense syslog  | ✅        | ✅     | ✅         |
| Zeek (VM07)      | ✅        | ✅     | ✅         |
| Velociraptor     | ✅        | ✅     | ✅ (46 procs DC01) |

---

## 7. Résumé KPI

| KPI              | Objectif     | Résultat    | Statut |
|------------------|-------------|-------------|--------|
| MTTD             | < 5 min     | 47 sec avg  | ✅      |
| Taux détection   | > 80%       | 100%        | ✅      |
| Taux FP          | < 5%        | < 0.001%    | ✅      |
| Coverage MITRE   | > 70%       | 78%         | ✅      |
| Pipeline SOAR    | Fonctionnel | Opérationnel| ✅      |
| Alertes TheHive  | > 100       | 350+        | ✅      |
| Velociraptor     | 2 clients   | 2 (DC01+WIN01) | ✅   |
