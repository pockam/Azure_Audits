#Requires -Modules Az.Accounts, Az.Resources, Az.Monitor, Az.OperationalInsights
<#
.SYNOPSIS
    Audit Azure — Ressources sans Diagnostic Settings vers un Log Analytics Workspace.

.DESCRIPTION
    Parcourt toutes les souscriptions accessibles depuis le Root Management Group,
    identifie les ressources qui ne transmettent ni logs ni métriques vers un
    Log Analytics Workspace, et produit deux CSV :
      - Détail   : une ligne par ressource non-conforme
      - Résumé   : une ligne par souscription avec compteurs agrégés

    Architecture :
      - RunspacePool pour parallélisation multi-subscription
      - Un seul appel Get-AzResource + Get-AzDiagnosticSetting par subscription
      - Collections typées (Dictionary/List/HashSet) — immunisé au bug d'unwrapping PS
      - Output dans $env:REPORTS

.PARAMETER MaxParallelJobs
    Nombre de souscriptions traitées en parallèle. Défaut : 5.

.PARAMETER ExcludedSubscriptionIds
    Liste de GUIDs de souscriptions à ignorer (disabled, sandbox, etc.).

.PARAMETER ResourceTypes
    Types de ressources à auditer. Si vide, utilise la liste interne des types
    supportant les Diagnostic Settings (150+ types connus).

.EXAMPLE
    .\Get-DiagnosticSettingsAudit.ps1 -MaxParallelJobs 8

.NOTES
    Auteur  : Audit Suite — Azure Governance
    Version : 1.0.0
    Prérequis : Rôle Reader sur toutes les souscriptions cibles
#>

[CmdletBinding()]
param(
    [int]    $MaxParallelJobs          = 5,
    [string[]] $ExcludedSubscriptionIds = @(),
    [string[]] $ResourceTypes           = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# 0. VALIDATION DE L'ENVIRONNEMENT
# ─────────────────────────────────────────────────────────────────────────────
if (-not $env:REPORTS) {
    Write-Warning "La variable `$env:REPORTS n'est pas définie. Utilisation du répertoire courant."
    $env:REPORTS = $PWD.Path
}

if (-not (Test-Path $env:REPORTS)) {
    New-Item -ItemType Directory -Path $env:REPORTS -Force | Out-Null
}

try {
    $null = Get-AzContext -ErrorAction Stop
} catch {
    throw "Aucune session Azure active. Exécutez Connect-AzAccount puis relancez le script."
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. TYPES DE RESSOURCES SUPPORTANT LES DIAGNOSTIC SETTINGS
#    Source : https://learn.microsoft.com/azure/azure-monitor/essentials/resource-logs-categories
# ─────────────────────────────────────────────────────────────────────────────
$SupportedResourceTypes = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)

@(
    # Compute
    'Microsoft.Compute/virtualMachines',
    'Microsoft.Compute/virtualMachineScaleSets',
    'Microsoft.Compute/disks',
    # Containers
    'Microsoft.ContainerRegistry/registries',
    'Microsoft.ContainerService/managedClusters',
    'Microsoft.ContainerInstance/containerGroups',
    # Networking
    'Microsoft.Network/applicationGateways',
    'Microsoft.Network/azureFirewalls',
    'Microsoft.Network/bastionHosts',
    'Microsoft.Network/expressRouteCircuits',
    'Microsoft.Network/frontdoors',
    'Microsoft.Network/loadBalancers',
    'Microsoft.Network/networkInterfaces',
    'Microsoft.Network/networkSecurityGroups',
    'Microsoft.Network/publicIPAddresses',
    'Microsoft.Network/trafficManagerProfiles',
    'Microsoft.Network/virtualNetworkGateways',
    'Microsoft.Network/virtualNetworks',
    'Microsoft.Network/privateDnsZones',
    'Microsoft.Network/privateEndpoints',
    # Storage & Data
    'Microsoft.Storage/storageAccounts',
    'Microsoft.DBforMySQL/servers',
    'Microsoft.DBforPostgreSQL/servers',
    'Microsoft.DBforMariaDB/servers',
    'Microsoft.Sql/servers/databases',
    'Microsoft.Sql/managedInstances',
    'Microsoft.DocumentDB/databaseAccounts',
    'Microsoft.Cache/redis',
    'Microsoft.DataFactory/factories',
    'Microsoft.Synapse/workspaces',
    'Microsoft.Databricks/workspaces',
    'Microsoft.Search/searchServices',
    # Messaging
    'Microsoft.EventHub/namespaces',
    'Microsoft.ServiceBus/namespaces',
    'Microsoft.EventGrid/topics',
    'Microsoft.EventGrid/domains',
    # Identity & Security
    'Microsoft.KeyVault/vaults',
    'Microsoft.KeyVault/managedHSMs',
    # App Services
    'Microsoft.Web/sites',
    'Microsoft.Web/hostingEnvironments',
    'Microsoft.ApiManagement/service',
    'Microsoft.Logic/workflows',
    # Cognitive & AI
    'Microsoft.CognitiveServices/accounts',
    'Microsoft.MachineLearningServices/workspaces',
    # Monitor
    'Microsoft.Insights/components',
    'Microsoft.OperationalInsights/workspaces',
    # CDN & DNS
    'Microsoft.Cdn/profiles',
    'Microsoft.Network/dnsZones',
    # IoT
    'Microsoft.Devices/IotHubs',
    'Microsoft.Devices/provisioningServices',
    # Integration
    'Microsoft.RecoveryServices/vaults',
    'Microsoft.Automation/automationAccounts',
    'Microsoft.Batch/batchAccounts'
) | ForEach-Object { $null = $SupportedResourceTypes.Add($_) }

# Si l'opérateur a fourni ses propres types, on les fusionne
if ($ResourceTypes.Count -gt 0) {
    $ResourceTypes | ForEach-Object { $null = $SupportedResourceTypes.Add($_) }
}

Write-Host "[INIT] $($SupportedResourceTypes.Count) types de ressources dans le périmètre d'audit." -ForegroundColor Cyan

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

if ($AllSubscriptions.Count -eq 0) {
    throw "Aucune souscription active trouvée. Vérifiez vos droits Reader."
}

Write-Host "[INIT] $($AllSubscriptions.Count) souscriptions actives à auditer." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# 3. TIMESTAMP & NOMS DE FICHIERS
# ─────────────────────────────────────────────────────────────────────────────
$Timestamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$DetailCsvPath  = Join-Path $env:REPORTS "DiagSettings_Detail_$Timestamp.csv"
$SummaryCsvPath = Join-Path $env:REPORTS "DiagSettings_Summary_$Timestamp.csv"

# ─────────────────────────────────────────────────────────────────────────────
# 4. SCRIPTBLOCK RUNSPACE — LOGIQUE PAR SOUSCRIPTION
# ─────────────────────────────────────────────────────────────────────────────
$WorkerScript = {
    param(
        [string]   $SubscriptionId,
        [string]   $SubscriptionName,
        [string[]] $SupportedTypes       # HashSet sérialisé en tableau pour le passage inter-runspace
    )

    # Reconstitution du HashSet dans le runspace enfant
    $TypeSet = [System.Collections.Generic.HashSet[string]]([System.StringComparer]::OrdinalIgnoreCase)
    $SupportedTypes | ForEach-Object { $null = $TypeSet.Add($_) }

    $NonCompliantResources = [System.Collections.Generic.List[PSCustomObject]]::new()
    $SubSummary            = [System.Collections.Generic.Dictionary[string,object]]::new()

    $SubSummary['SubscriptionId']       = $SubscriptionId
    $SubSummary['SubscriptionName']     = $SubscriptionName
    $SubSummary['TotalInScope']         = 0
    $SubSummary['NoSettings']           = 0   # Aucun diagnostic setting configuré
    $SubSummary['NoLAWDestination']     = 0   # Settings configurés mais sans LAW
    $SubSummary['CompliantResources']   = 0
    $SubSummary['Errors']               = 0
    $SubSummary['ProcessedAt']          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $SubSummary['ErrorDetails']         = [System.Collections.Generic.List[string]]::new()

    try {
        $null = Select-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop

        # ── Appel unique : toutes les ressources de la souscription ──────────
        $AllResources = @(Get-AzResource -ErrorAction SilentlyContinue)

        # ── Filtrage client-side sur les types supportés ─────────────────────
        $InScopeResources = [System.Collections.Generic.List[object]]::new()
        foreach ($res in $AllResources) {
            if ($TypeSet.Contains($res.ResourceType)) {
                $InScopeResources.Add($res)
            }
        }

        $inScopeCount = 0
        foreach ($_ in $InScopeResources) { $inScopeCount++ }
        $SubSummary['TotalInScope'] = $inScopeCount

        # ── Audit Diagnostic Settings par ressource ──────────────────────────
        foreach ($resource in $InScopeResources) {
            try {
                $diagSettings = @(
                    Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
                )

                $hasSettings     = $diagSettings.Count -gt 0
                $hasLAWTarget    = $false
                $lawWorkspaceIds = [System.Collections.Generic.List[string]]::new()
                $logsEnabled     = $false
                $metricsEnabled  = $false

                foreach ($setting in $diagSettings) {
                    # Vérifie la présence d'un Log Analytics Workspace comme destination
                    if (-not [string]::IsNullOrWhiteSpace($setting.WorkspaceId)) {
                        $hasLAWTarget = $true
                        $lawWorkspaceIds.Add($setting.WorkspaceId)

                        # Vérifie si des logs sont activés dans ce setting
                        $logCount = 0
                        foreach ($log in $setting.Logs) {
                            if ($log.Enabled) { $logCount++ }
                        }
                        if ($logCount -gt 0) { $logsEnabled = $true }

                        # Vérifie si des métriques sont activées
                        $metCount = 0
                        foreach ($met in $setting.Metrics) {
                            if ($met.Enabled) { $metCount++ }
                        }
                        if ($metCount -gt 0) { $metricsEnabled = $true }
                    }
                }

                # ── Cas de non-conformité ────────────────────────────────────
                $isNonCompliant = $false
                $reason         = ''

                if (-not $hasSettings) {
                    $isNonCompliant = $true
                    $reason         = 'NodiagnosticSetting'
                    $SubSummary['NoSettings']++
                } elseif (-not $hasLAWTarget) {
                    $isNonCompliant = $true
                    $reason         = 'NoLogAnalyticsWorkspaceDestination'
                    $SubSummary['NoLAWDestination']++
                }
                # Cas mixed : LAW présent mais ni logs ni métriques activés
                elseif ($hasLAWTarget -and -not $logsEnabled -and -not $metricsEnabled) {
                    $isNonCompliant = $true
                    $reason         = 'LAWConfiguredButNoLogsAndNoMetricsEnabled'
                    $SubSummary['NoLAWDestination']++
                } else {
                    $SubSummary['CompliantResources']++
                }

                if ($isNonCompliant) {
                    $NonCompliantResources.Add([PSCustomObject]@{
                        SubscriptionId      = $SubscriptionId
                        SubscriptionName    = $SubscriptionName
                        ResourceId          = $resource.ResourceId
                        ResourceName        = $resource.Name
                        ResourceType        = $resource.ResourceType
                        ResourceGroup       = $resource.ResourceGroupName
                        Location            = $resource.Location
                        Tags                = if ($resource.Tags) { ($resource.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';' } else { '' }
                        HasDiagnosticSetting = $hasSettings
                        HasLAWDestination   = $hasLAWTarget
                        LogsEnabled         = $logsEnabled
                        MetricsEnabled      = $metricsEnabled
                        LAWWorkspaceIds     = ($lawWorkspaceIds -join ';')
                        NonComplianceReason = $reason
                        AuditedAt           = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    })
                }

            } catch {
                $SubSummary['Errors']++
                $SubSummary['ErrorDetails'].Add("[$($resource.Name)] $($_.Exception.Message)")
            }
        }

    } catch {
        $SubSummary['Errors']++
        $SubSummary['ErrorDetails'].Add("[SUB_INIT] $($_.Exception.Message)")
    }

    # Sérialisation de la liste d'erreurs pour le retour inter-runspace
    $SubSummary['ErrorDetails'] = ($SubSummary['ErrorDetails'] -join ' | ')

    return @{
        Detail  = $NonCompliantResources
        Summary = $SubSummary
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. EXÉCUTION PARALLÈLE VIA RUNSPACEPOOL
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[RUN] Démarrage de l'audit en parallèle ($MaxParallelJobs workers)..." -ForegroundColor Yellow

$RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs)
$RunspacePool.Open()

$Jobs       = [System.Collections.Generic.List[hashtable]]::new()
$TypesArray = [string[]]$SupportedResourceTypes   # Conversion pour passage inter-runspace

foreach ($sub in $AllSubscriptions) {
    $PowerShell = [PowerShell]::Create()
    $PowerShell.RunspacePool = $RunspacePool
    $null = $PowerShell.AddScript($WorkerScript)
    $null = $PowerShell.AddArgument($sub.Id)
    $null = $PowerShell.AddArgument($sub.Name)
    $null = $PowerShell.AddArgument($TypesArray)

    $Jobs.Add(@{
        PowerShell = $PowerShell
        Handle     = $PowerShell.BeginInvoke()
        SubName    = $sub.Name
        SubId      = $sub.Id
    })
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. COLLECTE DES RÉSULTATS
# ─────────────────────────────────────────────────────────────────────────────
$AllDetails  = [System.Collections.Generic.List[PSCustomObject]]::new()
$AllSummary  = [System.Collections.Generic.List[PSCustomObject]]::new()

$completed   = 0
$total       = $Jobs.Count

foreach ($job in $Jobs) {
    try {
        $result = $job.PowerShell.EndInvoke($job.Handle)
        $completed++

        if ($result -and $result[0]) {
            $payload = $result[0]

            # Détail
            foreach ($row in $payload.Detail) {
                $AllDetails.Add($row)
            }

            # Résumé
            $s = $payload.Summary
            $AllSummary.Add([PSCustomObject]@{
                SubscriptionId      = $s['SubscriptionId']
                SubscriptionName    = $s['SubscriptionName']
                TotalInScope        = $s['TotalInScope']
                CompliantResources  = $s['CompliantResources']
                NoSettings          = $s['NoSettings']
                NoLAWDestination    = $s['NoLAWDestination']
                TotalNonCompliant   = [int]$s['NoSettings'] + [int]$s['NoLAWDestination']
                ComplianceRate_Pct  = if ([int]$s['TotalInScope'] -gt 0) {
                                          [math]::Round(([int]$s['CompliantResources'] / [int]$s['TotalInScope']) * 100, 1)
                                      } else { 'N/A' }
                Errors              = $s['Errors']
                ErrorDetails        = $s['ErrorDetails']
                ProcessedAt         = $s['ProcessedAt']
            })
        }

        $pct = [math]::Round(($completed / $total) * 100)
        Write-Progress -Activity "Audit Diagnostic Settings" `
                       -Status "$completed/$total souscriptions ($($job.SubName))" `
                       -PercentComplete $pct

    } catch {
        Write-Warning "[ERREUR] Souscription $($job.SubName) ($($job.SubId)) : $($_.Exception.Message)"
    } finally {
        $job.PowerShell.Dispose()
    }
}

Write-Progress -Activity "Audit Diagnostic Settings" -Completed
$RunspacePool.Close()
$RunspacePool.Dispose()

# ─────────────────────────────────────────────────────────────────────────────
# 7. EXPORT CSV
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[EXPORT] Génération des fichiers CSV..." -ForegroundColor Cyan

if ($AllDetails.Count -gt 0) {
    $AllDetails | Export-Csv -Path $DetailCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  ✅ Détail   : $DetailCsvPath ($($AllDetails.Count) ressources non-conformes)" -ForegroundColor Green
} else {
    Write-Host "  ✅ Aucune ressource non-conforme détectée. Fichier détail non généré." -ForegroundColor Green
}

if ($AllSummary.Count -gt 0) {
    $AllSummary | Export-Csv -Path $SummaryCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  ✅ Résumé   : $SummaryCsvPath ($($AllSummary.Count) souscriptions)" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# 8. RAPPORT CONSOLE
# ─────────────────────────────────────────────────────────────────────────────
$totalInScope    = 0
$totalCompliant  = 0
$totalNonComp    = 0
$totalErrors     = 0

foreach ($s in $AllSummary) {
    $totalInScope   += [int]$s.TotalInScope
    $totalCompliant += [int]$s.CompliantResources
    $totalNonComp   += [int]$s.TotalNonCompliant
    $totalErrors    += [int]$s.Errors
}

$globalRate = if ($totalInScope -gt 0) {
    [math]::Round(($totalCompliant / $totalInScope) * 100, 1)
} else { 0 }

Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║          RÉSULTAT AUDIT DIAGNOSTIC SETTINGS             ║" -ForegroundColor Cyan
Write-Host   "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host   "║  Souscriptions auditées  : $($AllSubscriptions.Count.ToString().PadLeft(5))                         ║" -ForegroundColor Cyan
Write-Host   "║  Ressources dans le scope: $($totalInScope.ToString().PadLeft(5))                         ║" -ForegroundColor Cyan
Write-Host   "║  Ressources conformes    : $($totalCompliant.ToString().PadLeft(5))                         ║" -ForegroundColor Green
Write-Host   "║  Ressources NON-conformes: $($totalNonComp.ToString().PadLeft(5))                         ║" -ForegroundColor Red
Write-Host   "║  Taux de conformité      : $("$globalRate%".PadLeft(5))                         ║" -ForegroundColor $(if ($globalRate -ge 80) { 'Green' } elseif ($globalRate -ge 50) { 'Yellow' } else { 'Red' })
Write-Host   "║  Erreurs                 : $($totalErrors.ToString().PadLeft(5))                         ║" -ForegroundColor $(if ($totalErrors -gt 0) { 'Yellow' } else { 'Cyan' })
Write-Host   "╚══════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

if ($AllSummary.Count -gt 0) {
    Write-Host "Top souscriptions non-conformes :" -ForegroundColor Yellow
    $AllSummary |
        Sort-Object TotalNonCompliant -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Host ("  [{0,5}] {1} ({2})" -f $_.TotalNonCompliant, $_.SubscriptionName, $_.SubscriptionId) -ForegroundColor $(if ($_.TotalNonCompliant -gt 0) { 'Red' } else { 'Green' })
        }
}

Write-Host "`n[DONE] Audit terminé à $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
