#Requires -Modules Az.Accounts, Az.Network
<#
.SYNOPSIS  Audit NSG — règles Inbound/Allow HTTP·HTTPS·RDP·SSH depuis toute source
.DESCRIPTION
    Génère dans $env:REPORTS :
      1. NSGRiskyRules_<ts>.csv         — détail par règle risquée
      2. NSGRiskyRules_Summary_<ts>.csv — synthèse par souscription
.PARAMETER MaxParallelJobs      RunspacePool (défaut:5, max:15)
.PARAMETER ExcludeSubscriptions Noms ou IDs à exclure
.EXAMPLE   .\Get-NSGRiskyRules.ps1 -MaxParallelJobs 8
#>
[CmdletBinding()]
param(
    [ValidateRange(1,15)][int]$MaxParallelJobs  = 5,
    [string[]]$ExcludeSubscriptions             = @()
)
Set-StrictMode -Version Latest; $ErrorActionPreference = "Stop"

# ── Helper log ────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message,[ValidateSet("INFO","WARN","ERROR","SUCCESS","DEBUG")][string]$Level="INFO")
    $c=@{INFO="Cyan";WARN="Yellow";ERROR="Red";SUCCESS="Green";DEBUG="DarkGray"}
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
    $_.State -eq "Enabled" -and $_.Name -notin $ExcludeSubscriptions -and $_.Id -notin $ExcludeSubscriptions
})
if ($subs.Count -eq 0) { Write-Log "Aucune souscription active." WARN; exit 0 }
Write-Log "Souscriptions : $($subs.Count) | Jobs : $MaxParallelJobs" INFO

# ── ScriptBlock runspace ──────────────────────────────────────────────────────
$sb = {
    param([string]$SubId, [string]$SubName)
    Import-Module Az.Accounts, Az.Network -EA SilentlyContinue

    # Constantes — définies une seule fois dans le runspace
    $riskyPorts  = @{ "80"="HTTP"; "443"="HTTPS"; "3389"="RDP"; "22"="SSH" }
    $openSources = [System.Collections.Generic.HashSet[string]]@("*","0.0.0.0","0.0.0.0/0","Internet","Any","<nxrange>")
    $riskMap     = @{ RDP="CRITICAL"; SSH="CRITICAL"; HTTP="HIGH"; HTTPS="HIGH" }

    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        Set-AzContext -SubscriptionId $SubId -EA Stop | Out-Null
        [array]$nsgs = @(Get-AzNetworkSecurityGroup -EA Stop)

        foreach ($nsg in $nsgs) {
            # Ressources attachées — pipeline court sur propriétés simples
            $subnets = ($nsg.Subnets           | ForEach-Object { Split-Path $_.Id -Leaf }) -join " | "
            $nics    = ($nsg.NetworkInterfaces | ForEach-Object { Split-Path $_.Id -Leaf }) -join " | "

            foreach ($rule in ($nsg.SecurityRules | Where-Object { $_.Direction -eq "Inbound" -and $_.Access -eq "Allow" })) {

                # Source ouverte ? — union des deux champs en une seule passe
                $allSrc = [System.Collections.Generic.List[string]]::new()
                if ($rule.SourceAddressPrefix)   { $allSrc.Add($rule.SourceAddressPrefix) }
                foreach ($p in $rule.SourceAddressPrefixes) { $allSrc.Add($p) }
                $srcOpen = $false
                foreach ($s in $allSrc) { if ($openSources.Contains($s)) { $srcOpen = $true; break } }
                if (-not $srcOpen) { continue }

                # Ports de la règle — union DestinationPortRange + DestinationPortRanges
                $rulePorts = [System.Collections.Generic.List[string]]::new()
                if ($rule.DestinationPortRange)  { $rulePorts.Add($rule.DestinationPortRange) }
                foreach ($p in $rule.DestinationPortRanges) { $rulePorts.Add($p) }

                # Matching ports risqués
                $matchedSvc   = [System.Collections.Generic.HashSet[string]]::new()
                $matchedPorts = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($rp in $rulePorts) {
                    if ($rp -eq "*") {
                        # Wildcard — ajouter tous les ports risqués en une passe
                        foreach ($kv in $riskyPorts.GetEnumerator()) {
                            $matchedSvc.Add($kv.Value)   | Out-Null
                            $matchedPorts.Add($kv.Key)   | Out-Null
                        }
                        break
                    }
                    if ($riskyPorts.ContainsKey($rp)) {
                        $matchedSvc.Add($riskyPorts[$rp]) | Out-Null; $matchedPorts.Add($rp) | Out-Null
                    } elseif ($rp -match '^(\d+)-(\d+)$') {
                        $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                        foreach ($kv in $riskyPorts.GetEnumerator()) {
                            if ([int]$kv.Key -ge $lo -and [int]$kv.Key -le $hi) {
                                $matchedSvc.Add($kv.Value) | Out-Null; $matchedPorts.Add($kv.Key) | Out-Null
                            }
                        }
                    }
                }
                if ($matchedSvc.Count -eq 0) { continue }

                # Niveau de risque — priorité CRITICAL > HIGH > MEDIUM
                $riskLevel = "MEDIUM"
                foreach ($svc in $matchedSvc) {
                    if ($riskMap[$svc] -eq "CRITICAL") { $riskLevel = "CRITICAL"; break }
                    if ($riskMap[$svc] -eq "HIGH")     { $riskLevel = "HIGH" }
                }

                $out.Add([PSCustomObject]@{
                    SubscriptionId   = $SubId
                    SubscriptionName = $SubName
                    NSGName          = $nsg.Name
                    ResourceGroup    = $nsg.ResourceGroupName
                    Location         = $nsg.Location
                    RuleName         = $rule.Name
                    Priority         = $rule.Priority
                    Protocol         = $rule.Protocol
                    SourceAddress    = $allSrc -join " | "
                    DestinationPort  = ($matchedPorts | Sort-Object) -join " | "
                    ExposedServices  = ($matchedSvc   | Sort-Object) -join " | "
                    RiskLevel        = $riskLevel
                    AttachedSubnets  = if ($subnets) { $subnets } else { "None" }
                    AttachedNICs     = if ($nics)    { $nics }    else { "None" }
                    AuditDate        = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
                })
            }
        }
    } catch {}
    return $out
}

# ── Exécution parallèle ───────────────────────────────────────────────────────
$pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs); $pool.Open()

[array]$jobs = @(foreach ($sub in $subs) {
    Write-Log "Job démarré : $($sub.Name)" DEBUG
    $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
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

if ($allResults.Count -eq 0) { Write-Log "Aucune règle NSG risquée détectée." SUCCESS; return $null }

# ── Export CSV Détail ─────────────────────────────────────────────────────────
$ts         = Get-Date -f "yyyyMMdd_HHmmss"
$detailPath = Join-Path $env:REPORTS "NSGRiskyRules_$ts.csv"
$riskOrder  = @{ CRITICAL=1; HIGH=2; MEDIUM=3 }
$allResults | Sort-Object { $riskOrder[$_.RiskLevel] }, SubscriptionName, NSGName, Priority |
    Export-Csv $detailPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Détail   → $detailPath" SUCCESS

# ── Agrégation synthèse (Dictionary + foreach — zéro pipeline .Count) ─────────
$agg = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()
foreach ($item in $allResults) {
    if (-not $agg.ContainsKey($item.SubscriptionName)) {
        $agg[$item.SubscriptionName] = [PSCustomObject]@{
            SubscriptionName=$item.SubscriptionName; SubscriptionId=$item.SubscriptionId
            TotalRules=0; Critical=0; High=0; Medium=0
            RDPExposed=0; SSHExposed=0; HTTPExposed=0; HTTPSExposed=0
            NSGs = [System.Collections.Generic.HashSet[string]]::new()
            RGs  = [System.Collections.Generic.HashSet[string]]::new()
            AuditDate=$item.AuditDate
        }
    }
    $e = $agg[$item.SubscriptionName]; $e.TotalRules++
    if ($item.RiskLevel -eq "CRITICAL")                                                { $e.Critical++ }
    if ($item.RiskLevel -eq "HIGH")                                                    { $e.High++ }
    if ($item.RiskLevel -eq "MEDIUM")                                                  { $e.Medium++ }
    if ($item.ExposedServices -like "*RDP*")                                           { $e.RDPExposed++ }
    if ($item.ExposedServices -like "*SSH*")                                           { $e.SSHExposed++ }
    if ($item.ExposedServices -like "*HTTPS*")                                         { $e.HTTPSExposed++ }
    elseif ($item.ExposedServices -like "*HTTP*")                                      { $e.HTTPExposed++ }
    $e.NSGs.Add($item.NSGName) | Out-Null; $e.RGs.Add($item.ResourceGroup) | Out-Null
}

# ── Export CSV Synthèse ───────────────────────────────────────────────────────
$summaryPath = Join-Path $env:REPORTS "NSGRiskyRules_Summary_$ts.csv"
$summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($k in ($agg.Keys | Sort-Object)) {
    $e = $agg[$k]
    $summaryRows.Add([PSCustomObject]@{
        SubscriptionName=$e.SubscriptionName; SubscriptionId=$e.SubscriptionId
        TotalRules=$e.TotalRules; Critical=$e.Critical; High=$e.High; Medium=$e.Medium
        RDPExposed=$e.RDPExposed; SSHExposed=$e.SSHExposed; HTTPExposed=$e.HTTPExposed; HTTPSExposed=$e.HTTPSExposed
        AffectedNSGCount=$e.NSGs.Count; AffectedNSGs=($e.NSGs | Sort-Object) -join " | "
        AffectedRGCount=$e.RGs.Count;   AffectedRGs =($e.RGs  | Sort-Object) -join " | "
        AuditDate=$e.AuditDate
    })
}
$summaryRows | Export-Csv $summaryPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Synthèse → $summaryPath" SUCCESS

# ── Console ───────────────────────────────────────────────────────────────────
Write-Log "══════════════════════════════════════════════════════════════════════" INFO
Write-Log "  SYNTHÈSE — Règles NSG Risquées par souscription" INFO
Write-Log "══════════════════════════════════════════════════════════════════════" INFO
foreach ($row in $summaryRows) {
    Write-Log ("  {0,-38} | CRIT:{1,3} | HIGH:{2,3} | RDP:{3,3} | SSH:{4,3} | HTTP:{5,3} | HTTPS:{6,3}" -f `
        $row.SubscriptionName,$row.Critical,$row.High,$row.RDPExposed,$row.SSHExposed,$row.HTTPExposed,$row.HTTPSExposed) WARN
}
Write-Log "══════════════════════════════════════════════════════════════════════" INFO
Write-Log "Total : $($allResults.Count) règle(s) risquée(s) | $($subs.Count) souscription(s)" WARN

return @{ Detail = $detailPath; Summary = $summaryPath }
