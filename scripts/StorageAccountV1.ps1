#Requires -Modules Az.Accounts, Az.Storage
<#
.SYNOPSIS
    Audite toutes les souscriptions Azure et identifie les comptes de stockage General Purpose v1 (Storage V1).

.DESCRIPTION
    - Parcourt toutes les souscriptions accessibles via Get-AzSubscription
    - Filtre les Storage Accounts dont le Kind est "Storage" (= GPv1)
    - Génère un CSV détaillé et un CSV de synthèse par souscription
    - Stocke les rapports dans $env:REPORTS
    - Exécution parallèle via RunspacePool (MaxParallelJobs configurable)

.PARAMETER MaxParallelJobs
    Nombre maximum de souscriptions traitées en parallèle. Défaut : 5.

.PARAMETER OutputPath
    Répertoire de sortie. Défaut : $env:REPORTS (défini dans votre profil PS).

.EXAMPLE
    .\Get-StorageAccountsGPv1.ps1
    .\Get-StorageAccountsGPv1.ps1 -MaxParallelJobs 8

.NOTES
    Auteur      : Lionel
    Version     : 1.0.0
    Prérequis   : Az.Accounts, Az.Storage | Connecté via Connect-AzAccount
    $env:REPORTS doit être défini dans votre profil PowerShell
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 10)]
    [int]$MaxParallelJobs = 5,

    [string]$OutputPath = $env:REPORTS
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')]
        [string]$Level = 'INFO'
    )
    $colors = @{
        INFO    = 'Cyan'
        WARN    = 'Yellow'
        ERROR   = 'Red'
        SUCCESS = 'Green'
        DEBUG   = 'Gray'
    }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION PRÉ-EXÉCUTION
# ─────────────────────────────────────────────────────────────────────────────
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-Log '$env:REPORTS n''est pas défini. Définissez-le dans votre profil ou passez -OutputPath.' -Level ERROR
    exit 1
}

if (-not (Test-Path $OutputPath)) {
    Write-Log "Création du répertoire de rapports : $OutputPath" -Level WARN
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Vérifie qu'on est bien connecté à Azure
try {
    $ctx = Get-AzContext
    if (-not $ctx) { throw }
    Write-Log "Contexte Azure actif : $($ctx.Account.Id) | Tenant : $($ctx.Tenant.Id)" -Level INFO
} catch {
    Write-Log 'Aucun contexte Azure actif. Lancez Connect-AzAccount avant ce script.' -Level ERROR
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# RÉCUPÉRATION DES SOUSCRIPTIONS
# ─────────────────────────────────────────────────────────────────────────────
Write-Log 'Récupération de la liste des souscriptions...' -Level INFO
$subscriptions = @(Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' })

if ($subscriptions.Count -eq 0) {
    Write-Log 'Aucune souscription active trouvée. Vérifiez vos droits.' -Level ERROR
    exit 1
}

Write-Log "$($subscriptions.Count) souscription(s) active(s) trouvée(s)." -Level SUCCESS

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPT BLOCK EXÉCUTÉ DANS CHAQUE RUNSPACE
# ─────────────────────────────────────────────────────────────────────────────
$scriptBlock = {
    param($SubId, $SubName)

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        Select-AzSubscription -SubscriptionId $SubId | Out-Null

        # Récupère TOUS les storage accounts en un seul appel API (perf optimale)
        $allStorageAccounts = @(Get-AzStorageAccount -ErrorAction Stop)

        # Filtre côté client : Kind = "Storage" => General Purpose v1
        $gpv1Accounts = @($allStorageAccounts | Where-Object { $_.Kind -eq 'Storage' })

        foreach ($sa in $gpv1Accounts) {

            # Calcul du statut HTTPS
            $httpsOnly = if ($sa.EnableHttpsTrafficOnly) { 'Oui' } else { 'Non ⚠️' }

            # Niveau de redondance
            $redundancy = switch ($sa.Sku.Name) {
                'Standard_LRS'  { 'LRS (Local)' }
                'Standard_GRS'  { 'GRS (Géo)' }
                'Standard_RAGRS'{ 'RA-GRS (Géo + Lecture)' }
                'Standard_ZRS'  { 'ZRS (Zonal)' }
                'Premium_LRS'   { 'Premium LRS' }
                default         { $sa.Sku.Name }
            }

            # Statut d'accès public aux blobs
            $publicAccess = if ($sa.AllowBlobPublicAccess -eq $true) { 'Oui ⚠️' } else { 'Non ✅' }

            # Chiffrement
            $keySource = $sa.Encryption.KeySource

            # TLS minimum
            $minTls = $sa.MinimumTlsVersion

            $results.Add([PSCustomObject]@{
                SubscriptionId        = $SubId
                SubscriptionName      = $SubName
                StorageAccountName    = $sa.StorageAccountName
                ResourceGroup         = $sa.ResourceGroupName
                Location              = $sa.Location
                Kind                  = $sa.Kind          # "Storage" = GPv1
                SkuName               = $sa.Sku.Name
                Redundancy            = $redundancy
                AccessTier            = if ($sa.AccessTier) { $sa.AccessTier } else { 'N/A' }
                HttpsOnly             = $httpsOnly
                PublicBlobAccess      = $publicAccess
                MinimumTlsVersion     = if ($minTls) { $minTls } else { 'Non défini ⚠️' }
                EncryptionKeySource   = $keySource
                AllowSharedKeyAccess  = if ($sa.AllowSharedKeyAccess -eq $false) { 'Non ✅' } else { 'Oui ⚠️' }
                CreationTime          = $sa.CreationTime
                Tags                  = ($sa.Tags | ConvertTo-Json -Compress -Depth 2)
                PrimaryEndpointBlob   = $sa.PrimaryEndpoints.Blob
                Recommendation        = 'Migrer vers GPv2 (aucun downtime, support des tiers chauds/froids)'
            })
        }
    } catch {
        # On retourne un enregistrement d'erreur pour ne pas perdre la traçabilité
        $results.Add([PSCustomObject]@{
            SubscriptionId        = $SubId
            SubscriptionName      = $SubName
            StorageAccountName    = 'ERREUR'
            ResourceGroup         = 'ERREUR'
            Location              = 'ERREUR'
            Kind                  = 'ERREUR'
            SkuName               = 'ERREUR'
            Redundancy            = 'ERREUR'
            AccessTier            = 'ERREUR'
            HttpsOnly             = 'ERREUR'
            PublicBlobAccess      = 'ERREUR'
            MinimumTlsVersion     = 'ERREUR'
            EncryptionKeySource   = 'ERREUR'
            AllowSharedKeyAccess  = 'ERREUR'
            CreationTime          = $null
            Tags                  = '{}'
            PrimaryEndpointBlob   = 'ERREUR'
            Recommendation        = "Erreur : $($_.Exception.Message)"
        })
    }

    return $results
}

# ─────────────────────────────────────────────────────────────────────────────
# EXÉCUTION PARALLÈLE VIA RUNSPACEPOOL
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "Démarrage de l'audit en parallèle (MaxParallelJobs=$MaxParallelJobs)..." -Level INFO

$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs, $iss, $Host)
$pool.Open()

$jobs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($sub in $subscriptions) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool

    $ps.AddScript($scriptBlock) | Out-Null
    $ps.AddArgument($sub.Id)    | Out-Null
    $ps.AddArgument($sub.Name)  | Out-Null

    $jobs.Add(@{
        PowerShell = $ps
        Handle     = $ps.BeginInvoke()
        SubName    = $sub.Name
    })
}

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTE DES RÉSULTATS
# ─────────────────────────────────────────────────────────────────────────────
$allResults   = [System.Collections.Generic.List[PSCustomObject]]::new()
$summaryData  = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()

foreach ($job in $jobs) {
    try {
        $jobResults = $job.PowerShell.EndInvoke($job.Handle)

        $gpv1Count  = 0
        $errorCount = 0

        foreach ($item in $jobResults) {
            $allResults.Add($item)
            if ($item.StorageAccountName -eq 'ERREUR') {
                $errorCount++
            } else {
                $gpv1Count++
            }
        }

        $status = if ($errorCount -gt 0) { 'PARTIEL' } else { 'OK' }
        Write-Log "[$($job.SubName)] GPv1 trouvés : $gpv1Count | Erreurs : $errorCount" -Level $(if ($errorCount -gt 0) {'WARN'} else {'SUCCESS'})

        $summaryData[$job.SubName] = [PSCustomObject]@{
            SubscriptionName   = $job.SubName
            GPv1Count          = $gpv1Count
            ErrorCount         = $errorCount
            Status             = $status
            AuditTimestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }

    } catch {
        Write-Log "Erreur collecte runspace [$($job.SubName)] : $($_.Exception.Message)" -Level ERROR
    } finally {
        $job.PowerShell.Dispose()
    }
}

$pool.Close()
$pool.Dispose()

# ─────────────────────────────────────────────────────────────────────────────
# EXPORT CSV
# ─────────────────────────────────────────────────────────────────────────────
$timestamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailCsv    = Join-Path $OutputPath "GPv1_StorageAccounts_Detail_$timestamp.csv"
$summaryCsv   = Join-Path $OutputPath "GPv1_StorageAccounts_Summary_$timestamp.csv"

Write-Log "Export CSV détaillé : $detailCsv" -Level INFO
$allResults | Export-Csv -Path $detailCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'

Write-Log "Export CSV synthèse : $summaryCsv" -Level INFO
$summaryData.Values | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'

# ─────────────────────────────────────────────────────────────────────────────
# RÉSUMÉ FINAL CONSOLE
# ─────────────────────────────────────────────────────────────────────────────
$totalGPv1 = 0
foreach ($s in $summaryData.Values) { $totalGPv1 += $s.GPv1Count }

Write-Log '─────────────────────────────────────────────────' -Level INFO
Write-Log "AUDIT TERMINÉ" -Level SUCCESS
Write-Log "  Souscriptions analysées : $($subscriptions.Count)" -Level INFO
Write-Log "  Comptes GPv1 détectés   : $totalGPv1" -Level $(if ($totalGPv1 -gt 0) {'WARN'} else {'SUCCESS'})
Write-Log "  Rapport détaillé        : $detailCsv" -Level INFO
Write-Log "  Rapport synthèse        : $summaryCsv" -Level INFO
Write-Log '─────────────────────────────────────────────────' -Level INFO

if ($totalGPv1 -gt 0) {
    Write-Log '⚠️  ACTION REQUISE : Des comptes GPv1 ont été détectés.' -Level WARN
    Write-Log '   Recommandation : Migrer vers General Purpose v2 (GPv2).' -Level WARN
    Write-Log '   La migration est gratuite, sans downtime, et ouvre les Access Tiers (Hot/Cool/Archive).' -Level WARN
    Write-Log '   Docs : https://learn.microsoft.com/en-us/azure/storage/common/storage-account-upgrade' -Level WARN
}

# ─────────────────────────────────────────────────────────────────────────────
# RETOUR DES DONNÉES (utilisable en pipeline ou en variable)
# ─────────────────────────────────────────────────────────────────────────────
return $allResults
