# SocForge — Procédure de Sauvegarde et Restauration

---

## 1. Stratégie de sauvegarde

| Composant             | Méthode              | Fréquence        | Rétention |
|-----------------------|----------------------|------------------|-----------|
| VMs VirtualBox        | Snapshots            | Avant chaque test | 3 derniers |
| Config Wazuh          | Git (ce repo)        | À chaque modif   | Illimitée |
| Alertes OpenSearch    | Export JSON          | Hebdomadaire     | 30 jours  |
| Règles personnalisées | Git                  | À chaque modif   | Illimitée |
| Artefacts DFIR        | Copie locale chiffrée | Après chaque hunt | 90 jours  |

---

## 2. Snapshots VirtualBox

### Créer un snapshot

```powershell
# Depuis l'hôte Windows (PowerShell)
VBoxManage snapshot "VM02-WAZUH" take "avant-test-2026-08-15" `
  --description "Avant session Purple Team Session 3"

VBoxManage snapshot "VM10-WIN01" take "avant-session3-2026-08-15" `
  --description "Avant SC-10/11/12"
```

### Lister les snapshots

```powershell
VBoxManage snapshot "VM02-WAZUH" list
VBoxManage snapshot "VM10-WIN01" list
```

### Restaurer un snapshot

```powershell
# Arrêter la VM d'abord
VBoxManage controlvm "VM10-WIN01" poweroff

# Restaurer
VBoxManage snapshot "VM10-WIN01" restore "avant-session3-2026-08-15"

# Redémarrer
VBoxManage startvm "VM10-WIN01" --type headless
```

### Supprimer les anciens snapshots (libérer espace)

```powershell
VBoxManage snapshot "VM10-WIN01" delete "nom-ancien-snapshot"
```

---

## 3. Sauvegarde des configurations Wazuh

### Configs critiques à sauvegarder

```bash
# Sur VM02-WAZUH
sudo tar -czf /tmp/wazuh-config-$(date +%Y%m%d).tar.gz \
  /var/ossec/etc/ossec.conf \
  /var/ossec/etc/rules/ \
  /var/ossec/etc/decoders/ \
  /etc/filebeat/filebeat.yml

# Copier vers le dépôt Git (après suppression des secrets)
scp socadmin@10.10.10.10:/tmp/wazuh-config-*.tar.gz ./backups/
```

### Restaurer les configurations

```bash
sudo tar -xzf wazuh-config-20260815.tar.gz -C /
sudo systemctl restart wazuh-manager
sudo systemctl restart filebeat
```

---

## 4. Export des alertes OpenSearch

### Export JSON d'une journée d'alertes

```bash
# Sur VM02-WAZUH
curl -sk -u admin:PASSWORD \
  "https://localhost:9200/wazuh-alerts-4.x-2026.08.15/_search?size=1000" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}}}' \
  > /tmp/alerts-export-2026-08-15.json

# Vérifier le nombre d'alertes exportées
python3 -c "import json; d=json.load(open('/tmp/alerts-export-2026-08-15.json')); print(d['hits']['total'])"
```

### Nettoyage des anciens indices (libérer espace disque)

```bash
# Supprimer les indices de plus de 30 jours
curl -sk -u admin:PASSWORD -X DELETE \
  "https://localhost:9200/wazuh-alerts-4.x-2026.07.*"
```

---

## 5. Sauvegarde TheHive

```bash
# Exporter les cas TheHive via API
curl -X GET http://10.10.10.20:9000/api/v1/case \
  -H "Authorization: Bearer API_KEY" \
  > thehive-cases-$(date +%Y%m%d).json

# Export complet de la base (Cassandra/Elasticsearch selon version)
# Voir documentation TheHive 5 pour la procédure complète
```

---

## 6. Restauration complète du lab

En cas de perte totale, ordre de restauration :

```
1. Restaurer le snapshot le plus récent de chaque VM
2. Démarrer VM01-FW
3. Démarrer VM02-WAZUH → vérifier les services
4. Réimporter les configs Wazuh depuis le repo Git
5. Démarrer les agents (WIN01, DC01, LINUX01)
6. Vérifier que les agents sont reconnectés
7. Démarrer SHUFFLE → vérifier le webhook
8. Démarrer THEHIVE → vérifier l'API
9. Rejouer une alerte de test pour valider la chaîne
```

### Test de restauration (à faire mensuellement)

```bash
# 1. Créer un snapshot de test
VBoxManage snapshot "VM02-WAZUH" take "test-restore-$(date +%Y%m%d)"

# 2. Simuler une panne (éteindre la VM)
VBoxManage controlvm "VM02-WAZUH" poweroff

# 3. Restaurer
VBoxManage snapshot "VM02-WAZUH" restore "test-restore-$(date +%Y%m%d)"
VBoxManage startvm "VM02-WAZUH" --type headless

# 4. Vérifier
sleep 90
curl -sk https://localhost:9200/_cluster/health | python3 -m json.tool
```

---

## 7. Synchronisation Git

```bash
# Sauvegarder tous les fichiers de config dans le repo
cd D:\SocForge
git add -A
git commit -m "backup: config et règles $(date +%Y-%m-%d)"
git push origin main
```

> Ne jamais inclure dans Git : mots de passe, clés API, certificats, fichiers `.env`.
