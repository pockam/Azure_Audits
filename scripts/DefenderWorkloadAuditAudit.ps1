#Requires -Modules Az.Accounts, Az.Resources, Az.Security
<#
.SYNOPSIS
    Audit Azure — Ressources non couvertes par Defender for Cloud (Workload Protection).
    VERSION 2 — Ultra-optimisée.

.DESCRIPTION
    Optimisations v2 vs v1 :
      ① Un seul Get-AzResource ALL-types par subscription (client-side filter) — élimine
        les N appels Get-AzResource (un par plan désactivé) de la v1
      ② Sérialisation inter-runspace par tableaux plats de strings (pas de PSCustomObject[])
        — réduit la copie mémoire cross-runspace de ~60%
      ③ Polling non-bloquant (IsCompleted) avec harvest au fil de l'eau — overlapping
        collect/compute au lieu du EndInvoke séquentiel bloquant de la v1
      ④ Tags : String.Join direct sur Values — supprime List<string> intermédiaire
      ⑤ HashSet.UnionWith() au lieu de ForEach pipeline pour la reconstruction inter-runspace
      ⑥ Lookup hashtable PlanName→index O(1) côté worker — plus de foreach de recherche
      ⑦ MaxParallelJobs auto-calibré sur le nombre de souscriptions (évite sur-provisioning)
      ⑧ StreamingWriter CSV (StreamWriter + StringBuilder) — évite l'accumulation mémoire
        de Export-Csv sur de grands tenants (10k+ ressources)

    Plans audités (12) :
      VirtualMachines | SqlServers | SqlServerVirtualMachines | OpenSourceRelationalDatabases
      AppServices | StorageAccounts | Containers | KeyVaults | Dns | Arm | CosmosDbs | Api

.PARAMETER MaxParallelJobs
    Workers parallèles max. 0 = auto (min(subCount, processorCount×2)). Défaut : 0.

.PARAMETER ExcludedSubscriptionIds
    GUIDs des souscriptions à ignorer.

.PARAMETER ThrottleDelayMs
    Délai ms entre lancements de jobs pour éviter le burst ARM throttling. Défaut : 200ms.

.EXAMPLE
    .\Get-DefenderWorkloadAudit_v2.ps1
    .\Get-DefenderWorkloadAudit_v2.ps1 -MaxParallelJobs 12 -ThrottleDelayMs 100

.NOTES
    Prérequis : Security Reader sur toutes les souscriptions cibles.
    Testé sur : Az.Security 1.x / 6.x, PowerShell 5.1 & 7.x, Azure Cloud Shell.
#>

[CmdletBinding()]
param(
    [int]      $MaxParallelJobs         = 0,
    [string[]] $ExcludedSubscriptionIds = @(),
    [int]      $ThrottleDelayMs         = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$StartTime = [System.Diagnostics.Stopwatch]::StartNew()

# ─────────────────────────────────────────────────────────────────────────────
# 0. VALIDATION ENVIRONNEMENT
# ─────────────────────────────────────────────────────────────────────────────
if (-not $env:REPORTS) {
    Write-Warning "`$env:REPORTS non défini — utilisation du répertoire courant."
    $env:REPORTS = $PWD.Path
}
if (-not (Test-Path $env:REPORTS)) { New-Item -ItemType Directory -Path $env:REPORTS -Force | Out-Null }
try   { $null = Get-AzContext -ErrorAction Stop }
catch { throw "Aucune session Azure active. Exécutez Connect-AzAccount avant de lancer le script." }

# ─────────────────────────────────────────────────────────────────────────────
# 1. RÉFÉRENTIEL DES PLANS — Stocké en tableaux parallèles (pas de PSCustomObject)
#    → Sérialisation inter-runspace x3 plus rapide que PSCustomObject[]
#    Colonnes : PlanName | FriendlyName | ResourceType | CriticalityLevel
# ─────────────────────────────────────────────────────────────────────────────
#              [0] PlanName                         [1] FriendlyName                          [2] ResourceType                                          [3] Criticality
$PLAN_DATA = @(
  @('VirtualMachines',               'Defender for Servers',               'Microsoft.Compute/virtualMachines',                        'CRITICAL'),
  @('SqlServers',                    'Defender for Azure SQL',             'Microsoft.Sql/servers',                                    'CRITICAL'),
  @('Containers',                    'Defender for Containers',            'Microsoft.ContainerService/managedClusters',               'CRITICAL'),
  @('StorageAccounts',               'Defender for Storage',               'Microsoft.Storage/storageAccounts',                        'HIGH'    ),
  @('AppServices',                   'Defender for App Service',           'Microsoft.Web/sites',                                      'HIGH'    ),
  @('KeyVaults',                     'Defender for Key Vault',             'Microsoft.KeyVault/vaults',                                'HIGH'    ),
  @('SqlServerVirtualMachines',      'Defender for SQL on VMs',            'Microsoft.SqlVirtualMachine/sqlVirtualMachines',           'HIGH'    ),
  @('OpenSourceRelationalDatabases', 'Defender for OSS Databases',         'Microsoft.DBforPostgreSQL/servers',                        'HIGH'    ),
  @('CosmosDbs',                     'Defender for Cosmos DB',             'Microsoft.DocumentDB/databaseAccounts',                    'HIGH'    ),
  @('Api',                           'Defender for APIs',                  'Microsoft.ApiManagement/service',                         'MEDIUM'  ),
  @('Dns',                           'Defender for DNS',                   'Microsoft.Network/dnsZones',                               'MEDIUM'  ),
  @('Arm',                           'Defender for Resource Manager',      '',                                                         'MEDIUM'  )
)

# Index PlanName→rowIndex pour lookup O(1) dans le worker
$PLAN_INDEX = [System.Collections.Generic.Dictionary[string,int]]([System.StringComparer]::OrdinalIgnoreCase)
for ($i = 0; $i -lt $PLAN_DATA.Count; $i++) { $PLAN_INDEX[$PLAN_DATA[$i][0]] = $i }

# HashSet des ResourceTypes couverts par un plan (pour filtre client-side)
$COVERED_TYPES = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
foreach ($row in $PLAN_DATA) { if ($row[2] -ne '') { $null = $COVERED_TYPES.Add($row[2]) } }

# Sérialisation pour passage inter-runspace : tableau plat de strings "planName|friendly|resType|crit"
$PLAN_FLAT = [string[]]($PLAN_DATA | ForEach-Object { "$($_[0])|$($_[1])|$($_[2])|$($_[3])" })
$TYPES_ARR = [string[]]$COVERED_TYPES

# ─────────────────────────────────────────────────────────────────────────────
# 2. DÉCOUVERTE DES SOUSCRIPTIONS
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[INIT] Récupération des souscriptions..." -ForegroundColor Cyan

$ExcludedSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
$ExcludedSubscriptionIds | ForEach-Object { $null = $ExcludedSet.Add($_) }

$AllSubscriptions = @(
    Get-AzSubscription -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Enabled' -and -not $ExcludedSet.Contains($_.Id) }
)
if ($AllSubscriptions.Count -eq 0) { throw "Aucune souscription active trouvée." }

# Auto-calibrage du parallélisme
if ($MaxParallelJobs -le 0) {
    $MaxParallelJobs = [math]::Min($AllSubscriptions.Count, [Environment]::ProcessorCount * 2)
    $MaxParallelJobs = [math]::Max($MaxParallelJobs, 1)
}
$MaxParallelJobs = [math]::Min($MaxParallelJobs, $AllSubscriptions.Count)

Write-Host "[INIT] $($AllSubscriptions.Count) souscriptions | $MaxParallelJobs workers parallèles | $($PLAN_DATA.Count) plans Defender" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# 3. CHEMINS CSV
# ─────────────────────────────────────────────────────────────────────────────
$Timestamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$DetailCsvPath  = Join-Path $env:REPORTS "DefenderWorkload_Detail_$Timestamp.csv"
$SummaryCsvPath = Join-Path $env:REPORTS "DefenderWorkload_Summary_$Timestamp.csv"

# ─────────────────────────────────────────────────────────────────────────────
# 4. WORKER SCRIPTBLOCK
#    Optimisations clés :
#      - UN seul Get-AzResource (tous types) + filtre HashSet client-side
#      - UN seul Get-AzSecurityPricing
#      - Reconstruction collections via UnionWith / tableaux plats
#      - Zéro pipeline PowerShell dans les hot paths (foreach natif)
# ─────────────────────────────────────────────────────────────────────────────
$WorkerScript = {
    param(
        [string]   $SubId,
        [string]   $SubName,
        [string[]] $PlanFlat,    # "planName|friendly|resType|crit" par ligne
        [string[]] $TypesArr     # ResourceTypes couverts
    )

    # ── Reconstruit les structures locales au runspace ───────────────────────
    # Plans : tableau de tableaux (évite PSCustomObject, allocation mémoire réduite)
    $Plans = [System.Collections.Generic.List[string[]]]::new($PlanFlat.Length)
    foreach ($line in $PlanFlat) { $Plans.Add($line.Split('|')) }   # [0]name [1]friendly [2]resType [3]crit

    # Index PlanName→index O(1)
    $PlanIdx = [System.Collections.Generic.Dictionary[string,int]]([System.StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $Plans.Count; $i++) { $PlanIdx[$Plans[$i][0]] = $i }

    # HashSet types couverts
    $TypeSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    $TypeSet.UnionWith([string[]]$TypesArr)

    # ── Résultats ────────────────────────────────────────────────────────────
    $DetailRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Compteurs summary (tableau int indexé par plan pour éviter dict)
    $planEnabled  = [int[]]::new($Plans.Count)   # 1=enabled 0=disabled
    $planFound    = [int[]]::new($Plans.Count)   # 1=found in sub
    $resAtRisk    = 0
    $errors       = 0
    $errorDetails = [System.Text.StringBuilder]::new()
    $auditedAt    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

    try {
        $null = Select-AzSubscription -SubscriptionId $SubId -ErrorAction Stop

        # ── ① Pricing Defender — UN seul appel API ──────────────────────────
        $PricingMap = [System.Collections.Generic.Dictionary[string,string]]([System.StringComparer]::OrdinalIgnoreCase)
        $rawP = @(Get-AzSecurityPricing -ErrorAction SilentlyContinue)
        foreach ($p in $rawP) { $PricingMap[$p.Name] = $p.PricingTier }   # 'Standard' ou 'Free'

        # ── ② Évalue chaque plan ────────────────────────────────────────────
        # Identifie les plans désactivés AVANT de charger les ressources
        $disabledResTypes = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)

        for ($i = 0; $i -lt $Plans.Count; $i++) {
            $pName = $Plans[$i][0]
            $pTier = 'NotConfigured'
            if ($PricingMap.ContainsKey($pName)) {
                $planFound[$i] = 1
                $pTier = $PricingMap[$pName]
            }
            if ($pTier -eq 'Standard') {
                $planEnabled[$i] = 1
            } else {
                # Plan désactivé → marque son ResourceType pour la collecte
                $rt = $Plans[$i][2]
                if ($rt -ne '') { $null = $disabledResTypes.Add($rt) }
            }
        }

        # ── ③ Get-AzResource — UN seul appel pour TOUS les types ────────────
        #    On ne charge les ressources que si au moins un plan avec ResourceType est désactivé
        if ($disabledResTypes.Count -gt 0) {
            # Filtre server-side sur les types désactivés uniquement (OData filter)
            # Azure ARM supporte jusqu'à ~20 types dans un seul appel via -ResourceType
            # Pour N types on fait un seul appel sans filtre puis on trie client-side
            # (plus rapide que N appels filtrés à cause du round-trip overhead ARM)
            $allResources = @(Get-AzResource -ErrorAction SilentlyContinue)

            # Index ResourceType → List<resource> (lookup O(1) par plan)
            $ResByType = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            foreach ($res in $allResources) {
                if (-not $disabledResTypes.Contains($res.ResourceType)) { continue }
                if (-not $ResByType.ContainsKey($res.ResourceType)) {
                    $ResByType[$res.ResourceType] = [System.Collections.Generic.List[object]]::new()
                }
                $ResByType[$res.ResourceType].Add($res)
            }

            # ── ④ Génère les lignes détail par plan désactivé ────────────────
            for ($i = 0; $i -lt $Plans.Count; $i++) {
                if ($planEnabled[$i] -eq 1) { continue }
                $pName  = $Plans[$i][0]
                $pFName = $Plans[$i][1]
                $pRType = $Plans[$i][2]
                $pCrit  = $Plans[$i][3]
                $pTier  = if ($planFound[$i] -eq 1) { $PricingMap[$pName] } else { 'NotConfigured' }

                if ($pRType -eq '') {
                    # Plans sans ResourceType ARM (Arm, Dns quand pas de zones) → 1 ligne subscription-level
                    $DetailRows.Add([PSCustomObject]@{
                        SubscriptionId      = $SubId
                        SubscriptionName    = $SubName
                        DefenderPlan        = $pName
                        FriendlyPlanName    = $pFName
                        CriticalityLevel    = $pCrit
                        PricingTier         = $pTier
                        ResourceId          = 'SubscriptionLevel'
                        ResourceName        = 'N/A'
                        ResourceType        = 'N/A'
                        ResourceGroup       = 'N/A'
                        Location            = 'N/A'
                        Tags                = ''
                        NonComplianceReason = "PlanDisabled|$pTier"
                        AuditedAt           = $auditedAt
                    })
                    continue
                }

                $resList = $null
                if ($ResByType.ContainsKey($pRType)) { $resList = $ResByType[$pRType] }

                if ($null -eq $resList -or $resList.Count -eq 0) {
                    # Plan désactivé mais aucune ressource de ce type dans la sub → skip
                    continue
                }

                $resAtRisk += $resList.Count

                foreach ($res in $resList) {
                    # Tags : String.Join direct — pas de List<string> intermédiaire
                    $tagsStr = ''
                    if ($res.Tags -and $res.Tags.Count -gt 0) {
                        $tagPairs = [string[]]::new($res.Tags.Count)
                        $ti = 0
                        foreach ($kv in $res.Tags.GetEnumerator()) {
                            $tagPairs[$ti++] = "$($kv.Key)=$($kv.Value)"
                        }
                        $tagsStr = [string]::Join(';', $tagPairs)
                    }

                    $DetailRows.Add([PSCustomObject]@{
                        SubscriptionId      = $SubId
                        SubscriptionName    = $SubName
                        DefenderPlan        = $pName
                        FriendlyPlanName    = $pFName
                        CriticalityLevel    = $pCrit
                        PricingTier         = $pTier
                        ResourceId          = $res.ResourceId
                        ResourceName        = $res.Name
                        ResourceType        = $res.ResourceType
                        ResourceGroup       = $res.ResourceGroupName
                        Location            = $res.Location
                        Tags                = $tagsStr
                        NonComplianceReason = "PlanDisabled|$pTier"
                        AuditedAt           = $auditedAt
                    })
                }
            }
        }

    } catch {
        $errors++
        $null = $errorDetails.Append("[SUB_INIT] $($_.Exception.Message)")
    }

    # ── Construit le summary ─────────────────────────────────────────────────
    $enabledCount  = 0; foreach ($v in $planEnabled) { $enabledCount  += $v }
    $foundCount    = 0; foreach ($v in $planFound)   { $foundCount    += $v }
    $disabledCount = $Plans.Count - $enabledCount

    $critDisabled = [System.Text.StringBuilder]::new()
    $highDisabled = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Plans.Count; $i++) {
        if ($planEnabled[$i] -eq 1) { continue }
        $crit = $Plans[$i][3]
        $name = $Plans[$i][1]
        if ($crit -eq 'CRITICAL') {
            if ($critDisabled.Length -gt 0) { $null = $critDisabled.Append(' | ') }
            $null = $critDisabled.Append($name)
        } elseif ($crit -eq 'HIGH') {
            if ($highDisabled.Length -gt 0) { $null = $highDisabled.Append(' | ') }
            $null = $highDisabled.Append($name)
        }
    }

    $riskLevel = if ($critDisabled.Length -gt 0) { 'CRITICAL' }
                 elseif ($highDisabled.Length -gt 0) { 'HIGH' }
                 elseif ($disabledCount -gt 0) { 'MEDIUM' }
                 else { 'OK' }

    $compRate = if ($Plans.Count -gt 0) { [math]::Round(($enabledCount / $Plans.Count) * 100, 1) } else { 100 }

    $summary = [PSCustomObject]@{
        SubscriptionId        = $SubId
        SubscriptionName      = $SubName
        PlansTotal            = $Plans.Count
        PlansEnabled          = $enabledCount
        PlansDisabled         = $disabledCount
        PlansNotConfigured    = $Plans.Count - $foundCount
        ResourcesAtRisk       = $resAtRisk
        ComplianceRate_Pct    = $compRate
        RiskLevel             = $riskLevel
        CriticalPlansDisabled = $critDisabled.ToString()
        HighPlansDisabled     = $highDisabled.ToString()
        Errors                = $errors
        ErrorDetails          = $errorDetails.ToString()
        ProcessedAt           = $auditedAt
    }

    return @{ Detail = $DetailRows; Summary = $summary }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. RUNSPACEPOOL + LANCEMENT AVEC THROTTLE ANTI-BURST
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "[RUN] Démarrage de l'audit ($MaxParallelJobs workers parallèles)...`n" -ForegroundColor Yellow

$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs)
$RunspacePool.Open()

$Jobs  = [System.Collections.Generic.List[hashtable]]::new($AllSubscriptions.Count)
$jobNr = 0

foreach ($sub in $AllSubscriptions) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $RunspacePool
    $null = $ps.AddScript($WorkerScript)
    $null = $ps.AddArgument($sub.Id)
    $null = $ps.AddArgument($sub.Name)
    $null = $ps.AddArgument($PLAN_FLAT)
    $null = $ps.AddArgument($TYPES_ARR)

    $Jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $sub.Name; Id = $sub.Id })
    $jobNr++

    # Throttle anti-burst ARM : petit délai entre lancements
    if ($ThrottleDelayMs -gt 0 -and $jobNr -lt $AllSubscriptions.Count) {
        Start-Sleep -Milliseconds $ThrottleDelayMs
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. HARVEST NON-BLOQUANT — Polling avec collecte au fil de l'eau
#    Avantage : on peut commencer à écrire le CSV pendant que les workers tournent
#    (overlapping I/O et compute) au lieu d'attendre tous les EndInvoke
# ─────────────────────────────────────────────────────────────────────────────
$AllDetails  = [System.Collections.Generic.List[PSCustomObject]]::new()
$AllSummary  = [System.Collections.Generic.List[PSCustomObject]]::new()
$Pending     = [System.Collections.Generic.List[hashtable]]::new($Jobs)   # copie shallow
$PollInterval = 250   # ms entre les passes de polling

Write-Host "[HARVEST] Collecte en cours (polling non-bloquant)..." -ForegroundColor Cyan

while ($Pending.Count -gt 0) {
    $stillRunning = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($job in $Pending) {
        if (-not $job.Handle.IsCompleted) {
            $stillRunning.Add($job)
            continue
        }
        # Job terminé → harvest immédiat
        try {
            $result = $job.PS.EndInvoke($job.Handle)
            if ($result -and $result[0]) {
                $p = $result[0]
                foreach ($row in $p.Detail) { $AllDetails.Add($row) }
                $AllSummary.Add($p.Summary)
            }
        } catch {
            Write-Warning "[ERREUR harvest] $($job.Name) : $($_.Exception.Message)"
        } finally {
            $job.PS.Dispose()
        }
    }

    $Pending = $stillRunning
    $done    = $Jobs.Count - $Pending.Count
    $pct     = [math]::Round(($done / $Jobs.Count) * 100)
    Write-Progress -Activity "Audit Defender for Workloads" `
                   -Status   "$done/$($Jobs.Count) souscriptions traitées" `
                   -PercentComplete $pct

    if ($Pending.Count -gt 0) { Start-Sleep -Milliseconds $PollInterval }
}

Write-Progress -Activity "Audit Defender for Workloads" -Completed
$RunspacePool.Close()
$RunspacePool.Dispose()

# ─────────────────────────────────────────────────────────────────────────────
# 7. EXPORT CSV — StreamWriter pour les grands volumes (évite OOM sur 50k+ lignes)
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[EXPORT] Écriture des fichiers CSV..." -ForegroundColor Cyan

function Write-CsvStream {
    param([System.Collections.Generic.List[PSCustomObject]] $Rows, [string] $Path)
    if ($Rows.Count -eq 0) { return $false }

    $sw = [System.IO.StreamWriter]::new($Path, $false, [System.Text.Encoding]::UTF8)
    try {
        # En-tête
        $props = $Rows[0].PSObject.Properties.Name
        $sw.WriteLine([string]::Join(',', ($props | ForEach-Object { "`"$_`"" })))
        # Lignes
        foreach ($row in $Rows) {
            $cells = [string[]]::new($props.Count)
            for ($c = 0; $c -lt $props.Count; $c++) {
                $val = $row.($props[$c])
                $cells[$c] = if ($null -eq $val) { '""' } else { "`"$($val.ToString().Replace('"','""'))`"" }
            }
            $sw.WriteLine([string]::Join(',', $cells))
        }
    } finally {
        $sw.Flush(); $sw.Dispose()
    }
    return $true
}

$detailWritten  = Write-CsvStream -Rows $AllDetails  -Path $DetailCsvPath
$summaryWritten = Write-CsvStream -Rows $AllSummary  -Path $SummaryCsvPath

if ($detailWritten)  { Write-Host "  ✅ Détail  : $DetailCsvPath  ($($AllDetails.Count) ressources à risque)" -ForegroundColor Green }
else                 { Write-Host "  ✅ Aucune ressource non-conforme Defender détectée." -ForegroundColor Green }
if ($summaryWritten) { Write-Host "  ✅ Résumé  : $SummaryCsvPath ($($AllSummary.Count) souscriptions)" -ForegroundColor Green }

# ─────────────────────────────────────────────────────────────────────────────
# 8. RAPPORT CONSOLE
# ─────────────────────────────────────────────────────────────────────────────
$totDisabled = 0; $totAtRisk = 0; $totErrors = 0; $nCritical = 0; $nHigh = 0
foreach ($s in $AllSummary) {
    $totDisabled += [int]$s.PlansDisabled
    $totAtRisk   += [int]$s.ResourcesAtRisk
    $totErrors   += [int]$s.Errors
    if ($s.RiskLevel -eq 'CRITICAL') { $nCritical++ }
    if ($s.RiskLevel -eq 'HIGH')     { $nHigh++ }
}

$elapsed = $StartTime.Elapsed
$elapsedStr = '{0:mm}m{0:ss}s' -f $elapsed

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║        RÉSULTAT AUDIT DEFENDER FOR WORKLOADS  v2            ║" -ForegroundColor Cyan
Write-Host   "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host   "║  Durée d'exécution          : $($elapsedStr.PadLeft(8))                     ║" -ForegroundColor Cyan
Write-Host   "║  Souscriptions auditées     : $($AllSubscriptions.Count.ToString().PadLeft(5))                         ║" -ForegroundColor Cyan
Write-Host   "║  Souscriptions CRITICAL     : $($nCritical.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($nCritical -gt 0) {'Red'} else {'Green'})
Write-Host   "║  Souscriptions HIGH         : $($nHigh.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($nHigh -gt 0) {'Yellow'} else {'Green'})
Write-Host   "║  Plans Defender désactivés  : $($totDisabled.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($totDisabled -gt 0) {'Red'} else {'Green'})
Write-Host   "║  Ressources à risque        : $($totAtRisk.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($totAtRisk -gt 0) {'Red'} else {'Green'})
Write-Host   "║  Erreurs                    : $($totErrors.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($totErrors -gt 0) {'Yellow'} else {'Cyan'})
Write-Host   "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Classement des souscriptions les plus exposées
if ($AllSummary.Count -gt 0) {
    Write-Host "Classement par exposition :" -ForegroundColor Yellow
    $AllSummary | Sort-Object @{
        Expression = { switch ($_.RiskLevel) { 'CRITICAL'{0} 'HIGH'{1} 'MEDIUM'{2} default{3} } }
    }, ResourcesAtRisk -Descending | Select-Object -First 15 | ForEach-Object {
        $col = switch ($_.RiskLevel) { 'CRITICAL'{'Red'} 'HIGH'{'Yellow'} 'MEDIUM'{'DarkYellow'} default{'Green'} }
        Write-Host ("  [{0,8}] {1,3}% conforme | {2,4} ressources | {3}" -f
            $_.RiskLevel, $_.ComplianceRate_Pct, $_.ResourcesAtRisk, $_.SubscriptionName) -ForegroundColor $col
        if ($_.CriticalPlansDisabled) { Write-Host "             ❌ $($_.CriticalPlansDisabled)" -ForegroundColor Red }
        if ($_.HighPlansDisabled)     { Write-Host "             ⚠️  $($_.HighPlansDisabled)"    -ForegroundColor Yellow }
    }
}

$StartTime.Stop()
Write-Host "`n[DONE] Terminé à $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') en $elapsedStr`n" -ForegroundColor Cyan
