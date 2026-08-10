# SocForge — Script de génération de rapport KPI
# Interroge Wazuh OpenSearch et génère un rapport Markdown des métriques SOC
# Usage: .\generate-kpi-report.ps1 -Days 7 -OutputPath .\metrics\kpi-report.md

param(
    [int]$Days = 7,
    [string]$OutputPath = ".\metrics\kpi-report.md",
    [string]$WazuhUrl = "https://localhost:12443",
    [string]$WazuhUser = "admin",
    [string]$WazuhPass = "S0cF0rge.Lab2024"
)

$ErrorActionPreference = "Stop"

# Ignorer les certificats auto-signés (lab uniquement)
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll

$headers = @{
    "Authorization" = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${WazuhUser}:${WazuhPass}"))
    "Content-Type"  = "application/json"
}

$fromDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ")
$toDate   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "[*] Interrogation Wazuh OpenSearch ($WazuhUrl) pour les $Days derniers jours..."

# ============================================================
# 1. Total alertes
# ============================================================
$queryTotal = @{
    query = @{
        range = @{
            "@timestamp" = @{ gte = $fromDate; lte = $toDate }
        }
    }
    track_total_hits = $true
    size = 0
} | ConvertTo-Json -Depth 5

try {
    $respTotal = Invoke-RestMethod -Uri "$WazuhUrl/wazuh-alerts-*/_count" `
        -Method POST -Headers $headers -Body $queryTotal
    $totalAlerts = $respTotal.count
} catch {
    $totalAlerts = "N/A (erreur: $_)"
}

# ============================================================
# 2. Alertes par niveau
# ============================================================
$queryByLevel = @{
    query = @{
        range = @{ "@timestamp" = @{ gte = $fromDate; lte = $toDate } }
    }
    size = 0
    aggs = @{
        by_level = @{
            terms = @{ field = "rule.level"; size = 15 }
        }
    }
} | ConvertTo-Json -Depth 6

try {
    $respLevel = Invoke-RestMethod -Uri "$WazuhUrl/wazuh-alerts-*/_search" `
        -Method POST -Headers $headers -Body $queryByLevel
    $levelBuckets = $respLevel.aggregations.by_level.buckets
} catch {
    $levelBuckets = @()
}

# ============================================================
# 3. Alertes par règle (top 10)
# ============================================================
$queryByRule = @{
    query = @{
        range = @{ "@timestamp" = @{ gte = $fromDate; lte = $toDate } }
    }
    size = 0
    aggs = @{
        top_rules = @{
            terms = @{ field = "rule.id"; size = 10 }
            aggs = @{
                desc = @{ terms = @{ field = "rule.description"; size = 1 } }
            }
        }
    }
} | ConvertTo-Json -Depth 8

try {
    $respRule = Invoke-RestMethod -Uri "$WazuhUrl/wazuh-alerts-*/_search" `
        -Method POST -Headers $headers -Body $queryByRule
    $ruleBuckets = $respRule.aggregations.top_rules.buckets
} catch {
    $ruleBuckets = @()
}

# ============================================================
# 4. Alertes par agent
# ============================================================
$queryByAgent = @{
    query = @{
        range = @{ "@timestamp" = @{ gte = $fromDate; lte = $toDate } }
    }
    size = 0
    aggs = @{
        by_agent = @{
            terms = @{ field = "agent.name"; size = 10 }
        }
    }
} | ConvertTo-Json -Depth 6

try {
    $respAgent = Invoke-RestMethod -Uri "$WazuhUrl/wazuh-alerts-*/_search" `
        -Method POST -Headers $headers -Body $queryByAgent
    $agentBuckets = $respAgent.aggregations.by_agent.buckets
} catch {
    $agentBuckets = @()
}

# ============================================================
# Génération du rapport Markdown
# ============================================================
$date = Get-Date -Format "yyyy-MM-dd HH:mm"
$report = @"
# Rapport KPI SocForge — Généré le $date

**Période analysée**: $fromDate → $toDate ($Days jours)
**Source**: Wazuh OpenSearch ($WazuhUrl)

---

## 1. Volume d'alertes

| Métrique                | Valeur        |
|-------------------------|---------------|
| Total alertes           | $totalAlerts  |
| Période                 | $Days jours   |
| Moyenne/jour            | $([math]::Round($totalAlerts / $Days, 0)) |

---

## 2. Répartition par niveau de sévérité

| Niveau | Nombre |
|--------|--------|
"@

foreach ($bucket in $levelBuckets | Sort-Object { [int]$_.key } -Descending) {
    $report += "| $($bucket.key) | $($bucket.doc_count) |`n"
}

$report += @"

---

## 3. Top 10 règles déclenchées

| Règle ID | Hits | Description |
|----------|------|-------------|
"@

foreach ($bucket in $ruleBuckets) {
    $desc = if ($bucket.desc.buckets.Count -gt 0) { $bucket.desc.buckets[0].key } else { "—" }
    $report += "| $($bucket.key) | $($bucket.doc_count) | $desc |`n"
}

$report += @"

---

## 4. Alertes par agent

| Agent | Hits |
|-------|------|
"@

foreach ($bucket in $agentBuckets) {
    $report += "| $($bucket.key) | $($bucket.doc_count) |`n"
}

$report += @"

---

*Rapport généré automatiquement par `scripts/report-generation/generate-kpi-report.ps1`*
*SocForge Lab — Environnement isolé local*
"@

# Écriture du fichier
$report | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "[+] Rapport généré: $OutputPath"
