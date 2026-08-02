# check-vms.ps1 — Vérification de l'état des VM SocForge
# Usage : .\check-vms.ps1

$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

$expectedVMs = @(
  "SF-VM01-FW",
  "SF-VM02-WAZUH",
  "SF-VM03-THEHIVE",
  "SF-VM04-CORTEX",
  "SF-VM05-MISP",
  "SF-VM06-SHUFFLE",
  "SF-VM07-NDR",
  "SF-VM08-DFIR-HUNT",
  "SF-VM09-DC01",
  "SF-VM10-WIN01",
  "SF-VM11-LINUX01",
  "SF-VM12-PURPLE"
)

Write-Host "=== SocForge VM Health Check ===" -ForegroundColor Cyan
Write-Host "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

$runningVMs = & $vbm list runningvms
$allVMs     = & $vbm list vms

$totalRAM = 0
$missingVMs = @()

foreach ($vm in $expectedVMs) {
  $exists  = $allVMs  | Select-String "`"$vm`""
  $running = $runningVMs | Select-String "`"$vm`""

  if ($exists) {
    $status = if ($running) { "RUNNING" } else { "off" }
    $color  = if ($running) { "Green"  } else { "Gray"  }

    # Lire la RAM configurée
    $info = & $vbm showvminfo $vm --machinereadable | Select-String "^memory="
    $ram  = if ($info) { [int]($info -replace "memory=","") } else { 0 }
    if ($running) { $totalRAM += $ram }

    Write-Host ("  {0,-25} [{1,-8}] {2,6} Mo" -f $vm, $status, $ram) -ForegroundColor $color
  } else {
    Write-Host ("  {0,-25} [MISSING ]" -f $vm) -ForegroundColor Red
    $missingVMs += $vm
  }
}

Write-Host ""
Write-Host "RAM totale des VM actives : $totalRAM Mo ($([math]::Round($totalRAM/1024,1)) Go)" -ForegroundColor Yellow
Write-Host "RAM hôte disponible       : $([math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1024,0)) Mo"

if ($missingVMs.Count -gt 0) {
  Write-Host ""
  Write-Host "VM manquantes : $($missingVMs -join ', ')" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Snapshots disponibles ===" -ForegroundColor Cyan
foreach ($vm in $expectedVMs) {
  $snaps = & $vbm snapshot $vm list 2>$null
  if ($snaps -and $snaps -notmatch "no snapshots") {
    Write-Host "  $vm :" -ForegroundColor White
    $snaps | Where-Object { $_ -match "Name:" } | ForEach-Object {
      Write-Host "    $_" -ForegroundColor Gray
    }
  }
}
