# Téléchargement des ISOs — SocForge

## ISOs nécessaires

### 1. Ubuntu Server 22.04 LTS (utilisée par VM02 à VM08, VM11)

- **URL** : https://ubuntu.com/download/server
- **Fichier** : `ubuntu-22.04.5-live-server-amd64.iso` (environ 2,1 Go)
- **SHA256 officiel** : vérifier sur https://ubuntu.com/download/server/thank-you

### 2. Kali Linux 2024.x (VM12-PURPLE)

- **URL** : https://www.kali.org/get-kali/#kali-installer-images
- **Fichier** : `kali-linux-2024.x-installer-amd64.iso` (environ 4 Go)
- **SHA256 officiel** : affiché sur la page de téléchargement

### 3. OPNsense 24.x (VM01-FW)

- **URL** : https://opnsense.org/download/
- **Edition** : `amd64 — dvd`
- **Fichier** : `OPNsense-24.x.x-dvd-amd64.iso.bz2` → décompresser avec 7-Zip
- **SHA256 officiel** : affiché sur la page de téléchargement

### 4. Windows Server 2022 Evaluation (VM09-DC01)

- **URL** : https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022
- **Fichier** : `SERVER_EVAL_x64FRE_en-us.iso` (environ 5,4 Go)
- **Durée** : 180 jours, renouvelable

### 5. Windows 11 Enterprise Evaluation (VM10-WIN01)

- **URL** : https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
- **Fichier** : `Entreprise.iso` (environ 5,8 Go)
- **Durée** : 90 jours

## Dossier de stockage recommandé

Créer un dossier dédié aux ISOs sur l'hôte :
```
D:\SocForge-ISOs\
  ubuntu-22.04.5-live-server-amd64.iso
  kali-linux-2024.x-installer-amd64.iso
  OPNsense-24.x.x-dvd-amd64.iso
  SERVER_EVAL_x64FRE_en-us.iso
  Win11_Ent_Eval.iso
```

## Vérification des hash SHA256 (PowerShell)

```powershell
# Vérifier l'intégrité d'un ISO avant utilisation
Get-FileHash "D:\SocForge-ISOs\ubuntu-22.04.5-live-server-amd64.iso" -Algorithm SHA256
```

## Attacher une ISO à une VM

```powershell
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# Exemple pour SF-VM02-WAZUH
& $vbm storageattach "SF-VM02-WAZUH" `
  --storagectl "IDE" `
  --port 0 --device 0 `
  --type dvddrive `
  --medium "D:\SocForge-ISOs\ubuntu-22.04.5-live-server-amd64.iso"
```

## Ordre d'installation recommandé

1. **SF-VM02-WAZUH** en premier (SIEM central, tout le reste en dépend)
2. **SF-VM10-WIN01** (endpoint principal de test)
3. **SF-VM09-DC01** (Active Directory)
4. **SF-VM11-LINUX01** (endpoint Linux)
5. **SF-VM01-FW** (firewall, après avoir validé les VMs essentielles)
6. Reste des VM SOC au fur et à mesure des phases
