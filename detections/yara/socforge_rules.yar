/*
   SocForge YARA Rules
   Déployé sur VM02-WAZUH: /var/ossec/etc/yara/rules/socforge_rules.yar
   Intégration: wazuh active-response + Wazuh YARA integration script
   Références: MITRE ATT&CK, VirusTotal community rules
   IMPORTANT: Ces règles sont pour un environnement lab isolé uniquement.
              Ne pas utiliser contre des systèmes non autorisés.
*/

import "pe"

/* ============================================================
   GROUPE: PowerShell Obfuscation (T1059.001 / T1027)
   ============================================================ */

rule SocForge_PowerShell_Encoded_Command
{
    meta:
        description = "Détecte PowerShell avec commande encodée en Base64"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1059.001, T1027"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $enc1 = "-enc " nocase
        $enc2 = "-EncodedCommand " nocase
        $enc3 = "FromBase64String(" nocase
    condition:
        ($ps1 and ($enc1 or $enc2)) or $enc3
}

rule SocForge_PowerShell_Download_Cradle
{
    meta:
        description = "Détecte un download cradle PowerShell (téléchargement+exécution en mémoire)"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1059.001, T1105"
        severity = "high"
    strings:
        $dl1 = "DownloadString(" nocase
        $dl2 = "DownloadFile(" nocase
        $dl3 = "WebClient" nocase
        $dl4 = "Net.WebClient" nocase
        $iex = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        ($dl1 or $dl2 or $dl3 or $dl4) and ($iex or $iex2)
}

/* ============================================================
   GROUPE: Mimikatz / Credential Dumping (T1003)
   ============================================================ */

rule SocForge_Mimikatz_Strings
{
    meta:
        description = "Détecte les strings caractéristiques de Mimikatz"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1003"
        severity = "critical"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::sam" nocase
        $s4 = "lsadump::dcsync" nocase
        $s5 = "privilege::debug" nocase
        $s6 = "sekurlsa::wdigest" nocase
        $s7 = "kerberos::list" nocase
        $s8 = { 6D 69 6D 69 6B 61 74 7A }
    condition:
        any of them
}

rule SocForge_Invoke_Mimikatz
{
    meta:
        description = "Détecte Invoke-Mimikatz (version PowerShell de Mimikatz)"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1003, T1059.001"
        severity = "critical"
    strings:
        $s1 = "Invoke-Mimikatz" nocase
        $s2 = "DumpCreds" nocase
        $s3 = "sekurlsa" nocase
    condition:
        2 of them
}

/* ============================================================
   GROUPE: Meterpreter / Empire Stager (T1059.001)
   ============================================================ */

rule SocForge_Meterpreter_Strings
{
    meta:
        description = "Détecte les strings de stager Meterpreter"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1059.001"
        severity = "critical"
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "ReflectiveDllInjection" nocase
        $s3 = "METERPRETER" nocase
        $s4 = { 4D 65 74 65 72 70 72 65 74 65 72 }
        $s5 = "stdapi_sys_process_getpid" nocase
    condition:
        any of them
}

rule SocForge_PowerShell_Empire
{
    meta:
        description = "Détecte des indicateurs du framework Empire"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1059.001"
        severity = "critical"
    strings:
        $s1 = "Empire" nocase fullword
        $s2 = "PowerShell Empire" nocase
        $s3 = "Invoke-Empire" nocase
        $s4 = "EmPyre" nocase
        $s5 = "BC-Security/Empire" nocase
    condition:
        any of them
}

/* ============================================================
   GROUPE: Lateral Movement (T1021)
   ============================================================ */

rule SocForge_PsExec_Usage
{
    meta:
        description = "Détecte l'utilisation de PsExec pour le mouvement latéral"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1021.002, T1570"
        severity = "medium"
    strings:
        $s1 = "psexec" nocase
        $s2 = "PSEXESVC" nocase
        $s3 = { 50 53 45 58 45 53 56 43 }
    condition:
        any of them
}

/* ============================================================
   GROUPE: Suspicious PE (T1055 Process Injection)
   ============================================================ */

rule SocForge_Packed_Executable
{
    meta:
        description = "Détecte un exécutable potentiellement packé (peu de sections, haute entropie)"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "T1027"
        severity = "medium"
    condition:
        pe.is_pe and
        pe.number_of_sections < 3 and
        pe.overlay.size > 0 and
        for any s in pe.sections: (s.name contains "UPX" or s.name contains ".nsp")
}

/* ============================================================
   GROUPE: Atomic Red Team Artefacts (lab only)
   ============================================================ */

rule SocForge_AtomicRedTeam_Artifacts
{
    meta:
        description = "Détecte des artefacts générés par Atomic Red Team (tests lab)"
        author = "SocForge Lab"
        date = "2026-08-01"
        mitre = "Multiple"
        severity = "info"
    strings:
        $s1 = "Invoke-AtomicTest" nocase
        $s2 = "AtomicRedTeam" nocase
        $s3 = "atomic-red-team" nocase
        $s4 = "T1059.001" nocase
        $s5 = "PathToAtomicsFolder" nocase
    condition:
        any of them
}
