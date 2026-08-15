# SocForge — Guide de Dépannage

---

## 1. Wazuh

### Agent déconnecté dans le dashboard

```bash
# Vérifier le statut de l'agent (sur la VM source)
sudo systemctl status wazuh-agent

# Redémarrer
sudo systemctl restart wazuh-agent

# Vérifier les logs
sudo tail -50 /var/ossec/logs/ossec.log
```

Causes fréquentes : IP du manager incorrecte dans `ossec.conf`, pare-feu bloquant le port 1514.

---

### Filebeat 401 Unauthorized (OpenSearch)

Symptôme : `wazuh-alerts-*` vide, logs Filebeat montrent `401`.

```bash
sudo tail -20 /var/log/filebeat/filebeat

# Vérifier les credentials dans filebeat.yml
sudo grep -A3 "output.elasticsearch:" /etc/filebeat/filebeat.yml
```

Fix : écrire les credentials directement dans `filebeat.yml` (username/password) plutôt que via keystore si le keystore est corrompu. Redémarrer ensuite :

```bash
sudo systemctl restart filebeat
```

---

### Dashboard Wazuh inaccessible (port 443)

```bash
sudo systemctl status wazuh-dashboard
sudo journalctl -u wazuh-dashboard --no-pager -n 30
```

Vérifier que l'indexer est opérationnel :

```bash
curl -sk -u admin:PASSWORD https://localhost:9200/_cluster/health | python3 -m json.tool
```

---

### Index OpenSearch manquant

```bash
# Lister les indices existants
curl -sk -u admin:PASSWORD https://localhost:9200/_cat/indices/wazuh-alerts-* | sort

# Vérifier le nombre de documents
curl -sk -u admin:PASSWORD https://localhost:9200/wazuh-alerts-4.x-$(date +%Y.%m.%d)/_count
```

---

## 2. Agents Windows (Sysmon / Wazuh Agent)

### Sysmon ne génère pas d'événements

```powershell
# Vérifier que Sysmon est en cours d'exécution
Get-Service Sysmon64

# Vérifier les événements dans l'Event Viewer
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Si absent : réinstaller Sysmon avec la config SwiftOnSecurity.

---

### Agent Wazuh Windows ne se connecte pas

```powershell
# Vérifier le service
Get-Service WazuhSvc

# Logs agent Windows
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

Vérifier `C:\Program Files (x86)\ossec-agent\ossec.conf` → champ `<address>` doit pointer vers l'IP Wazuh.

---

### PowerShell Script Block Logging non actif

```powershell
# Vérifier la clé de registre
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

# Activer manuellement si absent
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1
```

---

## 3. Shuffle SOAR

### Webhook ne reçoit pas les alertes Wazuh

1. Vérifier que l'URL du webhook Shuffle est correcte dans `ossec.conf` (Wazuh Manager).
2. Vérifier que le port Shuffle (3001) est accessible depuis le réseau lab.
3. Tester manuellement :

```bash
curl -X POST http://10.10.10.30:3001/api/v1/hooks/HOOK_ID \
  -H "Content-Type: application/json" \
  -d '{"rule":{"id":"100131","description":"test"},"agent":{"name":"win01"}}'
```

---

### Workflow Shuffle bloqué / en erreur

- Aller dans Shuffle UI → onglet **Runs** → cliquer sur l'exécution en erreur.
- Inspecter le nœud rouge pour le message d'erreur.
- Problèmes fréquents : champ JSON manquant, clé API TheHive expirée, timeout Cortex.

---

## 4. TheHive

### Impossible de créer une alerte via API

```bash
# Test de l'API TheHive
curl -X GET http://10.10.10.20:9000/api/status \
  -H "Authorization: Bearer API_KEY"
```

Vérifier que le compte API a les droits `org-admin` ou `analyst`.

---

### TheHive ne démarre pas (Java heap)

```bash
sudo journalctl -u thehive --no-pager -n 50 | grep -i "error\|heap\|memory"
```

Fix : éditer `/etc/thehive/application.conf` et réduire le heap Java dans le script de démarrage.

---

## 5. Velociraptor

### Client non visible dans le serveur

```bash
# Vérifier le service client (Windows)
Get-Service Velociraptor

# Vérifier la config client (fichier client.config.yaml)
# L'URL du serveur doit correspondre exactement
```

---

### Hunt ne retourne aucun résultat

- Vérifier que les clients cibles sont **online** (point vert dans l'interface).
- Vérifier les permissions du compte analyste (rôle `investigator` minimum).
- Re-lancer le hunt avec un timeout plus long (300s).

---

## 6. RAM / Performance

### VMs trop lentes / swap excessif

```bash
# Sur l'hôte Windows : vérifier la RAM utilisée
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name, WorkingSet

# Réduire le heap OpenSearch sur Wazuh
sudo grep -r "Xms\|Xmx" /etc/wazuh-indexer/jvm.options
```

Règle : ne jamais dépasser 2 VMs actives simultanément (limite 16 Go RAM hôte).

---

## 7. Problèmes réseau VirtualBox

### VMs ne se pingent pas

```bash
# Vérifier l'interface réseau VirtualBox
VBoxManage list hostonlyifs
VBoxManage list intnets

# Vérifier que les VMs sont sur le même réseau interne "socforge-mgmt"
VBoxManage showvminfo "VM02-WAZUH" | grep NIC
```

---

### Perte de connectivité après redémarrage hôte

Les interfaces VirtualBox Host-Only peuvent changer d'IP après redémarrage. Vérifier :

```bash
# Sur l'hôte Windows
ipconfig | findstr "192.168\|10.10"
```

Reconfigurer l'IP statique de la VM si nécessaire.

---

## 8. Commandes de diagnostic rapide

```bash
# Wazuh : état de tous les services
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard filebeat

# OpenSearch : santé du cluster
curl -sk -u admin:PASSWORD https://localhost:9200/_cluster/health?pretty

# Agents connectés
curl -sk -u wazuh-wui:PASSWORD https://localhost:55000/agents?status=active \
  -H "Authorization: Bearer $(curl -sk -u wazuh-wui:PASSWORD -X POST \
  https://localhost:55000/security/user/authenticate | python3 -c \
  'import sys,json; print(json.load(sys.stdin)["data"]["token"])')"
```
