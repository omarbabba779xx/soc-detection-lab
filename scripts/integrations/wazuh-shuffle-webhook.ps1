# SocForge — Wazuh → Shuffle SOAR Integration Script
# Envoie les alertes Wazuh critiques vers le webhook Shuffle
# Usage: Exécuter depuis VM02-WAZUH ou hôte Windows avec accès réseau lab
# Prérequis: PowerShell 5.1+, accès à l'API Wazuh et au webhook Shuffle

param(
    [string]$WazuhHost    = "https://10.10.10.10:55000",
    [string]$WazuhUser    = "admin",
    [string]$WazuhPass    = "S0cF0rge.Lab2024",
    [string]$ShuffleHook  = "http://10.10.10.30:3001/api/v1/hooks/webhook_socforge_wazuh",
    [int]   $MinLevel     = 10,
    [int]   $PollSeconds  = 30
)

# Désactiver la vérification SSL pour le lab (certificat auto-signé)
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAll : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) { return true; }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-WazuhToken {
    $creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${WazuhUser}:${WazuhPass}"))
    $resp = Invoke-RestMethod -Uri "$WazuhHost/security/user/authenticate" `
        -Method POST `
        -Headers @{ "Authorization" = "Basic $creds" }
    return $resp.data.token
}

function Get-WazuhAlerts {
    param([string]$Token, [int]$Level)
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    $body = @{
        query = @{
            bool = @{
                must = @(
                    @{ range = @{ "@timestamp" = @{ gte = "now-${PollSeconds}s" } } }
                    @{ range = @{ "rule.level" = @{ gte = $Level } } }
                )
            }
        }
        size = 50
        sort = @(@{ "@timestamp" = @{ order = "desc" } })
    } | ConvertTo-Json -Depth 10

    $resp = Invoke-RestMethod -Uri "$WazuhHost/wazuh-alerts-4.x-*/_search" `
        -Method POST -Headers $headers -Body $body
    return $resp.hits.hits
}

function Send-ToShuffle {
    param([object]$Alert)
    $source = $Alert._source
    $payload = @{
        alert_id    = $Alert._id
        timestamp   = $source."@timestamp"
        rule_id     = $source.rule.id
        rule_level  = $source.rule.level
        rule_desc   = $source.rule.description
        rule_groups = $source.rule.groups -join ","
        mitre_id    = $source.rule.mitre.id -join ","
        agent_name  = $source.agent.name
        agent_ip    = $source.agent.ip
        src_ip      = $source.data.srcip
        dest_ip     = $source.data.dstip
        full_log    = $source.full_log
        location    = $source.location
    } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-RestMethod -Uri $ShuffleHook -Method POST `
            -ContentType "application/json" -Body $payload
        Write-Host "[$(Get-Date -f 'HH:mm:ss')] Sent alert $($Alert._id) rule $($source.rule.id) level $($source.rule.level) → Shuffle OK"
    } catch {
        Write-Warning "[$(Get-Date -f 'HH:mm:ss')] Failed to send alert $($Alert._id): $_"
    }
}

# Main loop
Write-Host "SocForge Wazuh→Shuffle bridge started"
Write-Host "  Wazuh:  $WazuhHost"
Write-Host "  Shuffle: $ShuffleHook"
Write-Host "  Min level: $MinLevel | Poll: every ${PollSeconds}s"
Write-Host "Press Ctrl+C to stop."

$sent = @{}

while ($true) {
    try {
        $token  = Get-WazuhToken
        $alerts = Get-WazuhAlerts -Token $token -Level $MinLevel

        foreach ($alert in $alerts) {
            if (-not $sent.ContainsKey($alert._id)) {
                Send-ToShuffle -Alert $alert
                $sent[$alert._id] = $true
            }
        }
        # Purge old sent IDs (keep last 1000)
        if ($sent.Count -gt 1000) {
            $keys = @($sent.Keys) | Select-Object -Last 500
            $sent  = @{}
            foreach ($k in $keys) { $sent[$k] = $true }
        }
    } catch {
        Write-Warning "Error in main loop: $_"
    }
    Start-Sleep -Seconds $PollSeconds
}
