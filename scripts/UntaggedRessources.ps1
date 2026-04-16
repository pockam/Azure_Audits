#Requires -Modules Az.Accounts, Az.Resources
<#
.SYNOPSIS  Audit ressources Azure non taguées — Multi-Subscription
.DESCRIPTION
    Génère deux rapports dans $env:REPORTS :
      1. UntaggedResources_<timestamp>.csv     — toutes les ressources non conformes (CSV détail)
      2. UntaggedResources_Summary_<timestamp>.csv — synthèse agrégée par souscription (CSV synthèse)
.PARAMETER RequiredTags         Tags obligatoires (défaut: Environment, Owner, CostCenter)
.PARAMETER MaxParallelJobs      Parallélisme RunspacePool (défaut: 5, max: 15)
.PARAMETER ExcludeSubscriptions Noms ou IDs de souscriptions à exclure
.EXAMPLE   .\Get-UntaggedResources.ps1 -RequiredTags @("Env","Owner") -MaxParallelJobs 8
#>
[CmdletBinding()]
param(
    [string[]]$RequiredTags         = @("Environment","Owner","CostCenter"),
    [ValidateRange(1,15)][int]$MaxParallelJobs = 5,
    [string[]]$ExcludeSubscriptions = @()
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
Write-Log "Souscriptions : $($subs.Count) | Tags requis : $($RequiredTags -join ', ') | Jobs : $MaxParallelJobs" INFO

# ── ScriptBlock runspace ──────────────────────────────────────────────────────
$sb = {
    param([string]$SubId, [string]$SubName, [string[]]$RequiredTags)
    Import-Module Az.Accounts, Az.Resources -EA SilentlyContinue
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        Set-AzContext -SubscriptionId $SubId -EA Stop | Out-Null
        foreach ($r in (Get-AzResource -EA Stop)) {
            $noTags      = (-not $r.Tags -or $r.Tags.Count -eq 0)
            $missingList = [System.Collections.Generic.List[string]]::new()
            foreach ($tag in $RequiredTags) {
                if ($noTags -or -not $r.Tags.ContainsKey($tag)) { $missingList.Add($tag) }
            }
            if ($missingList.Count -eq 0) { continue }
            $out.Add([PSCustomObject]@{
                SubscriptionId   = $SubId
                SubscriptionName = $SubName
                ResourceName     = $r.Name
                ResourceType     = $r.ResourceType
                ResourceGroup    = $r.ResourceGroupName
                Location         = $r.Location
                ResourceId       = $r.ResourceId
                AnomalyType      = if ($noTags) { "NoTags" } else { "MissingRequiredTags" }
                MissingTags      = $missingList -join " | "
                ExistingTags     = if ($r.Tags) {
                                       ($r.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "
                                   } else { "" }
                AuditDate        = (Get-Date -f "yyyy-MM-dd HH:mm:ss")
            })
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
    $ps.AddScript($sb).AddArgument($sub.Id).AddArgument($sub.Name).AddArgument($RequiredTags) | Out-Null
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

if ($allResults.Count -eq 0) { Write-Log "Aucune ressource non conforme détectée." SUCCESS; return $null }

# ── Timestamps & chemins ──────────────────────────────────────────────────────
$ts          = Get-Date -f "yyyyMMdd_HHmmss"
$detailPath  = Join-Path $env:REPORTS "UntaggedResources_$ts.csv"
$summaryPath = Join-Path $env:REPORTS "UntaggedResources_Summary_$ts.csv"

# ── CSV 1 — Détail complet, trié par souscription / RG / ressource ────────────
$allResults | Sort-Object SubscriptionName, ResourceGroup, ResourceName |
    Export-Csv $detailPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Détail   → $detailPath" SUCCESS

# ── Agrégation par souscription (foreach + Dictionary — sans pipeline .Count) ──
$summary = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()
foreach ($item in $allResults) {
    if (-not $summary.ContainsKey($item.SubscriptionName)) {
        $summary[$item.SubscriptionName] = [PSCustomObject]@{
            SubscriptionName   = $item.SubscriptionName
            SubscriptionId     = $item.SubscriptionId
            TotalNonCompliant  = 0
            NoTags             = 0
            MissingRequiredTags= 0
            AffectedRGs        = [System.Collections.Generic.HashSet[string]]::new()
            AffectedResTypes   = [System.Collections.Generic.HashSet[string]]::new()
            AuditDate          = $item.AuditDate
        }
    }
    $entry = $summary[$item.SubscriptionName]
    $entry.TotalNonCompliant++
    if ($item.AnomalyType -eq "NoTags")              { $entry.NoTags++ }
    if ($item.AnomalyType -eq "MissingRequiredTags") { $entry.MissingRequiredTags++ }
    $entry.AffectedRGs.Add($item.ResourceGroup)      | Out-Null
    $entry.AffectedResTypes.Add($item.ResourceType)  | Out-Null
}

# ── CSV 2 — Synthèse par souscription ────────────────────────────────────────
$summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($subName in ($summary.Keys | Sort-Object)) {
    $e = $summary[$subName]
    $summaryRows.Add([PSCustomObject]@{
        SubscriptionName    = $e.SubscriptionName
        SubscriptionId      = $e.SubscriptionId
        TotalNonCompliant   = $e.TotalNonCompliant
        NoTags              = $e.NoTags
        MissingRequiredTags = $e.MissingRequiredTags
        AffectedRGCount     = $e.AffectedRGs.Count
        AffectedRGs         = ($e.AffectedRGs | Sort-Object) -join " | "
        AffectedResTypes    = ($e.AffectedResTypes | Sort-Object) -join " | "
        AuditDate           = $e.AuditDate
    })
}
$summaryRows | Export-Csv $summaryPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
Write-Log "CSV Synthèse → $summaryPath" SUCCESS

# ── Affichage console de la synthèse ─────────────────────────────────────────
Write-Log "─────────────────────────────────────────────────────────────" INFO
Write-Log "  SYNTHÈSE PAR SOUSCRIPTION" INFO
Write-Log "─────────────────────────────────────────────────────────────" INFO
foreach ($row in $summaryRows) {
    Write-Log ("  {0,-40} | Total:{1,4} | NoTags:{2,4} | Missing:{3,4} | RGs:{4,3}" -f `
        $row.SubscriptionName, $row.TotalNonCompliant, $row.NoTags, $row.MissingRequiredTags, $row.AffectedRGCount) WARN
}
Write-Log "─────────────────────────────────────────────────────────────" INFO
Write-Log "Total global : $($allResults.Count) ressources non conformes sur $($subs.Count) souscriptions" WARN

return @{ Detail = $detailPath; Summary = $summaryPath }
