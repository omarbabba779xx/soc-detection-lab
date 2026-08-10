# Requêtes VQL — Velociraptor SocForge

Requêtes VQL pour les hunts et investigations dans Velociraptor (`VM08-DFIR-HUNT`).

---

## 1. Liste des processus (pslist)

```vql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username,
       format(format="%v", args=CreateTime) AS Started,
       hash(path=Exe, hashselect="MD5,SHA256") AS Hashes
FROM pslist()
ORDER BY CreateTime DESC
```

---

## 2. Processus non signés (suspects)

```vql
SELECT Pid, Name, Exe, CommandLine,
       Authenticode(filename=Exe).Trusted AS Signed
FROM pslist()
WHERE NOT Authenticode(filename=Exe).Trusted
AND NOT Exe =~ "(?i)\\\\Windows\\\\(System32|SysWOW64)\\\\"
```

---

## 3. Connexions réseau actives

```vql
SELECT c.Pid, p.Name AS ProcessName, c.Status,
       c.Laddr.IP AS LocalIP, c.Laddr.Port AS LocalPort,
       c.Raddr.IP AS RemoteIP, c.Raddr.Port AS RemotePort
FROM netstat() AS c
JOIN pslist() AS p ON c.Pid = p.Pid
WHERE c.Status = "ESTABLISHED"
AND NOT c.Raddr.IP IN ("127.0.0.1", "::1", "")
ORDER BY c.Raddr.Port
```

---

## 4. Clés Run dans le registre (persistance T1547.001)

```vql
SELECT Key.FullPath AS RegistryKey, Name, Data.value AS Value
FROM read_reg_key(globs=[
  "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/**",
  "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce/**",
  "HKEY_CURRENT_USER/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/**"
])
```

---

## 5. Tâches planifiées (persistance T1053.005)

```vql
SELECT Name, Path, Command, Arguments, Author,
       format(format="%v", args=NextRunTime) AS NextRun
FROM scheduled_tasks()
WHERE NOT Path =~ "(?i)\\\\Microsoft\\\\Windows\\\\"
```

---

## 6. Accès à LSASS (T1003 - Credential Dumping)

```vql
SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime,
       EventData.SourceImage AS Attacker,
       EventData.TargetImage AS Target,
       EventData.GrantedAccess AS Access
FROM parse_evtx(
  filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
)
WHERE System.EventID.Value = 10
AND EventData.TargetImage =~ "lsass.exe"
AND NOT EventData.SourceImage =~ "(?i)(MsMpEng|csrss|wininit|lsass)\\.exe"
ORDER BY EventTime DESC
```

---

## 7. Hunt — Événements PowerShell encodés (T1059.001)

```vql
SELECT timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime,
       EventData.NewProcessName AS ProcessPath,
       EventData.CommandLine AS CmdLine,
       EventData.SubjectUserName AS User
FROM parse_evtx(
  filename="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
)
WHERE System.EventID.Value = 4688
AND EventData.NewProcessName =~ "(?i)powershell"
AND EventData.CommandLine =~ "(?i)(-enc|-EncodedCommand|IEX|DownloadString)"
ORDER BY EventTime DESC
```

---

## 8. Dump d'artifacts réseau complet (pour analyse forensique)

```vql
-- Collect multiple artifacts
SELECT * FROM chain(
    a={SELECT * FROM netstat()},
    b={SELECT * FROM pslist()},
    c={SELECT * FROM users()}
)
```

---

## 9. Chercher fichiers récents dans %TEMP% (dépôt de payload)

```vql
SELECT FullPath, Size,
       format(format="%v", args=Mtime) AS Modified,
       hash(path=FullPath, hashselect="MD5,SHA256") AS Hashes
FROM glob(globs=[
  "C:\\Users\\**\\AppData\\Local\\Temp\\*.exe",
  "C:\\Users\\**\\AppData\\Local\\Temp\\*.ps1",
  "C:\\Users\\**\\AppData\\Local\\Temp\\*.bat",
  "C:\\Windows\\Temp\\*.exe"
])
WHERE Mtime > now() - 86400
ORDER BY Mtime DESC
```

---

## 10. Services installés récemment (T1543.003)

```vql
SELECT Name, DisplayName, PathName, StartMode, State,
       format(format="%v", args=InstallDate) AS Installed
FROM wmi(
  query="SELECT * FROM Win32_Service WHERE InstallDate IS NOT NULL",
  namespace="root/cimv2"
)
ORDER BY Installed DESC
```
