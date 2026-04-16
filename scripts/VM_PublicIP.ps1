#Requires -Modules Az.Accounts, Az.Compute, Az.Network
<#
.SYNOPSIS  Audit des VMs Azure exposées avec une IP Publique — Multi-Subscription
.DESCRIPTION
    Génère deux rapports dans $env:REPORTS :
      1. VMPublicIP_<timestamp>.csv         — détail de chaque VM avec IP publique
      2. VMPublicIP_Summary_<timestamp>.csv — synthèse agrégée par souscription
.PARAMETER MaxParallelJobs      Parallélisme RunspacePool (défaut: 5, max: 15)
.PARAMETER ExcludeSubscriptions Noms ou IDs de souscriptions à exclure
.EXAMPLE   .\Get-VMPublicIP.ps1 -MaxParallelJobs 8 -ExcludeSubscriptions @("Sub-Sandbox")
#>
[CmdletBinding()]
param(
    [ValidateRange(1,15)][int]$MaxParallelJobs  = 5,
    [string[]]$ExcludeSubscriptions             = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helper log ────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR","SUCCESS","DEBUG")][string]$Level = "INFO")
    $c = @{ INFO="Cyan"; WARN="Yellow"; ERROR="Red"; SUCCESS="Green"; DEBUG="DarkGray" }
    Write-Host "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $c[$Level]
}

# ── Pré-requis ────────────────────────────────────────────────────────────────
try   { $ctx = Get-AzContext -EA Stop; if (-not $ctx) { throw } }
catch { Write-Log "Non connecté. Exécutez Connect-AzAccount." ERROR; exit 1 }
Write-Log "Connecté : $($ctx.Account.Id)" SUCCESS

if (-not $env:REPORTS) { Write-Log "`$env:REPORTS non défini !" ERROR; exit 1 }
if (-not (Test-Path $env:REPORTS)) { New-Item $env:REPORTS -ItemType Directory -Force | Out-Null }

# ── Souscriptions ─────────────────────────────────────────────────────────────
[array]$subs = @(Get-AzSubscription | Where-Object {
    $_.State -eq "Enabled" -and
    $_.Name  -notin $ExcludeSubscriptions -and
    $_.Id    -notin $ExcludeSubscriptions
})
if ($subs.Count -eq 0) { Write-Log "Aucune souscription active." WARN; exit 0 }
Write-Log "Souscriptions : $($subs.Count) | Jobs : $MaxParallelJobs" INFO

# ── ScriptBlock runspace ──────────────────────────────────────────────────────
$sb = {
    param([string]$SubId, [string]$SubName)
    Import-Module Az.Accounts, Az.Compute, Az.Network -EA SilentlyContinue

    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        Set-AzContext -SubscriptionId $SubId -EA Stop | Out-Null

        # Récupération en une passe — classification client-side
        $allNics  = Get-AzNetworkInterface -EA Stop
        $allPips  = Get-AzPublicIpAddress  -EA Stop
        $allVMs   = Get-AzVM              -EA Stop

        # Index PIP par ID pour lookup O(1)
        $pipIndex = [System.Collections.Generic.Dictionary[string, object]]::new()
        foreach ($pip in $allPips) { $pipIndex[$pip.Id.ToLower()] = $pip }

        # Index VM par ID pour enrichissement
        $vmIndex = [System.Collections.Generic.Dictionary[string, object]]::new()
        foreach ($vm in $allVMs) { $vmIndex[$vm.Id.ToLower()] = $vm }

        foreach ($nic in $allNics) {
            # NIC doit être attachée à une VM
            if (-not $nic.VirtualMachine) { continue }

            foreach ($ipConfig in $nic.IpConfigurations) {
                if (-not $ipConfig.PublicIpAddress) { continue }

                $pipId  = $ipConfig.PublicIpAddress.Id.ToLower()
                $pip    = if ($pipIndex.ContainsKey($pipId)) { $pipIndex[$pipId] } else { $null }
                $vmId   = $nic.VirtualMachine.Id.ToLower()
                $vm     = if ($vmIndex.ContainsKey($vmId))  { $vmIndex[$vmId]  } else { $null }

                $out.Add([PSCustomObject]@{
                    SubscriptionId     = $SubId
                    SubscriptionName   = $SubName
                    VMName             = if ($vm)  { $vm.Name }                  else { Split-Path $nic.VirtualMachine.Id -Leaf }
                    ResourceGroup      = $nic.ResourceGroupName
                    Location           = $nic.Location
                    VMSize             = if ($vm)  { $vm.HardwareProfile.VmSize } else { "N/A" }
                    PowerState         = if ($vm)  { ($vm.Statuses | Where-Object { $_.Code -like "PowerState*" } | Select-Object -First 1).DisplayStatus } else { "N/A" }
                    OSType             = if ($vm)  { $vm.StorageProfile.OsDisk.OsType } else { "N/A" }
                    NICName            = $nic.Name
                    IPConfigName       = $ipConfig.Name
                    PrivateIP          = $ipConfig.PrivateIpAddress
                    PublicIPName       = if ($pip) { $pip.Name }                 else { Split-Path $ipConfig.PublicIpAddress.Id -Leaf }
                    PublicIPAddress    = if ($pip) { $pip.IpAddress }            else { "N/A" }
                    PublicIPSku        = if ($pip) { $pip.Sku.Name }             else { "N/A" }
                    PublicIPAllocation = if ($pip) { $pip.PublicIpAllocationMethod } else { "N/A" }
                    DNSLabel           = if ($pip -and $pip.DnsSettings) { $pip.DnsSettings.Fqdn } else { "" }
                    NSGOnNIC           = if ($nic.NetworkSecurityGroup) { Split-Path $nic.NetworkSecurityGroup.Id -Leaf } else { "None" }
                    Tags               = if ($vm -and $vm.Tags) {
                                             ($vm.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "
                                         } else { "" }
                    AuditDate          = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
                })
            }
        }
    } catch {}
    return $out
}

# ── Exécution parallèle ───────────────────────────────────────────────────────
$pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs)
$pool.Open()

[array]$jobs = @(foreach ($sub in $subs) {
    Write-Log "Job démarré : $($sub.Name)" DEBUG
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $ps.AddScript($sb).AddArgument($sub.Id).AddArgument($sub.Name) | Out-Null
    @{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $sub.Name }
})

$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$i = 0
foreach ($job in $jobs) {
    try   { foreach ($r in $job.PS.EndInvoke($job.Handle)) { $allResults.Add($r) }; $i++ }
    catch { Write-Log "Erreur job $($job.Name) : $_" ERROR }
    finally { $job.PS.Dispose() }
    Write-Log "[$i/$($jobs.Count)] Terminé : $($job.Name)" SUCCESS
}
$pool.Close(); $pool.Dispose()

if ($allResults.Count -eq 0) { Write-Log "Aucune VM avec IP publique détectée." SUCCESS; return $null }

# ── Timestamps & chemins ──────────────────────────────────────────────────────
$ts          = Get-Date -f "yyyyMMdd_HHmmss"
$detailPath  = Join-Path $env:REPORTS "VMPublicIP_$ts.csv"
$summaryPath = Join-Path $env:REPORTS "VMPublicIP_Summary_$ts.csv"

# ── CSV 1 — Détail complet ────────────────────────────────────────────────────
$allResults | Sort-Object SubscriptionName, ResourceGroup, VMName |
    Export-Csv $detailPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Détail   → $detailPath" SUCCESS

# ── Agrégation par souscription (Dictionary + foreach — sans pipeline .Count) ──
$summary = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()
foreach ($item in $allResults) {
    if (-not $summary.ContainsKey($item.SubscriptionName)) {
        $summary[$item.SubscriptionName] = [PSCustomObject]@{
            SubscriptionName  = $item.SubscriptionName
            SubscriptionId    = $item.SubscriptionId
            TotalVMsExposed   = 0
            StaticIPs         = 0
            DynamicIPs        = 0
            WithNSG           = 0
            WithoutNSG        = 0
            AffectedRGs       = [System.Collections.Generic.HashSet[string]]::new()
            VMNames           = [System.Collections.Generic.HashSet[string]]::new()
            AuditDate         = $item.AuditDate
        }
    }
    $e = $summary[$item.SubscriptionName]
    $e.TotalVMsExposed++
    if ($item.PublicIPAllocation -eq "Static")  { $e.StaticIPs++ }
    if ($item.PublicIPAllocation -eq "Dynamic") { $e.DynamicIPs++ }
    if ($item.NSGOnNIC -ne "None")              { $e.WithNSG++ } else { $e.WithoutNSG++ }
    $e.AffectedRGs.Add($item.ResourceGroup) | Out-Null
    $e.VMNames.Add($item.VMName)            | Out-Null
}

# ── CSV 2 — Synthèse par souscription ────────────────────────────────────────
$summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($subName in ($summary.Keys | Sort-Object)) {
    $e = $summary[$subName]
    $summaryRows.Add([PSCustomObject]@{
        SubscriptionName  = $e.SubscriptionName
        SubscriptionId    = $e.SubscriptionId
        TotalVMsExposed   = $e.TotalVMsExposed
        StaticIPs         = $e.StaticIPs
        DynamicIPs        = $e.DynamicIPs
        WithNSG           = $e.WithNSG
        WithoutNSG        = $e.WithoutNSG
        AffectedRGCount   = $e.AffectedRGs.Count
        AffectedRGs       = ($e.AffectedRGs | Sort-Object) -join " | "
        VMNames           = ($e.VMNames     | Sort-Object) -join " | "
        AuditDate         = $e.AuditDate
    })
}
$summaryRows | Export-Csv $summaryPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Synthèse → $summaryPath" SUCCESS

# ── Affichage console ─────────────────────────────────────────────────────────
Write-Log "─────────────────────────────────────────────────────────────────────" INFO
Write-Log "  SYNTHÈSE PAR SOUSCRIPTION — VMs avec IP Publique" INFO
Write-Log "─────────────────────────────────────────────────────────────────────" INFO
foreach ($row in $summaryRows) {
    Write-Log ("  {0,-40} | Total:{1,3} | Static:{2,3} | Dynamic:{3,3} | SansNSG:{4,3} | RGs:{5,3}" -f `
        $row.SubscriptionName, $row.TotalVMsExposed, $row.StaticIPs, $row.DynamicIPs, $row.WithoutNSG, $row.AffectedRGCount) WARN
}
Write-Log "─────────────────────────────────────────────────────────────────────" INFO
Write-Log "Total global : $($allResults.Count) VM(s) exposées sur $($subs.Count) souscription(s)" WARN

return @{ Detail = $detailPath; Summary = $summaryPath }
