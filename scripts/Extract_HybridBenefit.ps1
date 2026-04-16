#Requires -Modules Az.Accounts, Az.Compute, Az.Sql, Az.SqlVirtualMachine, Az.Resources
<#
.SYNOPSIS
    Audit Azure Hybrid Benefit (AHB) — état actif et opportunités d'activation.

.DESCRIPTION
    Parcourt toutes les souscriptions Azure accessibles et identifie :
      1. Les ressources avec AHB déjà activé  → économies mensuelles réalisées
      2. Les ressources éligibles sans AHB     → économies potentielles si activation

    Ressources couvertes :
      - VMs Windows Server  (AHB ≈ 40 % d'économie sur la licence OS)
      - VMs SQL Server      (AHB ≈ 55 % d'économie sur la licence SQL)
      - Azure SQL Database  (AHB ≈ 30 % d'économie sur la licence SQL)
      - Azure SQL Managed Instance (AHB ≈ 30 %)

    Résultats exportés dans :
      /home/pockam/clouddrive/reports/AzHybridBenefitAudit_<timestamp>.csv
      /home/pockam/clouddrive/reports/AzHybridBenefitAudit_<timestamp>_Summary.csv

.PARAMETER OutputDir
    Répertoire de sortie (défaut : /home/pockam/clouddrive/reports)

.PARAMETER SubscriptionIds
    Liste optionnelle de souscriptions à auditer. Si vide → toutes les souscriptions accessibles.

.PARAMETER IncludeDisabledSubscriptions
    Inclure les souscriptions désactivées (Disabled/Warned). Défaut : $false

.PARAMETER ExchangeRateEURUSD
    Taux de change EUR/USD utilisé pour convertir les estimations (défaut : 0.92)

.EXAMPLE
    .\Get-AzHybridBenefitAudit.ps1

.EXAMPLE
    .\Get-AzHybridBenefitAudit.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -OutputDir "C:\Reports"

.NOTES
    Auteur  : Script généré pour audit FinOps AHB
    Version : 2.0.0
    Date    : 2026-03-20

    Taux d'économie utilisés (conservateurs, basés sur documentation Microsoft mars 2026) :
      Windows Server VM   : 40 % du coût total VM (part licence OS)
      SQL Server VM       : 55 % du coût total VM (part licence SQL)
      Azure SQL DB/MI     : 30 % du coût total (part licence SQL)

    ⚠  Ces estimations sont basées sur des ratios documentés par Microsoft.
       Pour des chiffres précis, utilisez le Azure Pricing Calculator avec vos SKUs exacts.
       Les prix réels varient selon région, tier, taille, Reserved Instances, etc.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDir = "/home/pockam/clouddrive/reports",

    [Parameter()]
    [string[]]$SubscriptionIds = @(),

    [Parameter()]
    [switch]$IncludeDisabledSubscriptions,

    [Parameter()]
    [double]$ExchangeRateEURUSD = 0.92
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTES — Taux d'économie AHB (source : Microsoft, mars 2026)
# ─────────────────────────────────────────────────────────────────────────────
$AHB_SAVINGS_RATE = @{
    "WindowsVM"  = 0.40   # ~40 % d'économie sur coût VM Windows (part OS licence)
    "SqlVM"      = 0.55   # ~55 % d'économie sur coût VM SQL Server (part SQL licence)
    "SqlDB"      = 0.30   # ~30 % d'économie sur SQL Database vCore
    "SqlMI"      = 0.30   # ~30 % d'économie sur SQL Managed Instance
}

# Prix de référence mensuels approximatifs par vCore (USD) pour calcul d'estimation
# Source: Azure pricing Standard_D4s_v5 approximation — à titre indicatif uniquement
$VCPU_PRICE_USD_MONTHLY = @{
    "WindowsVM"  = 35.00  # USD/vCPU/mois approximation
    "SqlVM"      = 90.00  # USD/vCPU/mois avec SQL EE approximation
    "SqlDB"      = 185.00 # USD/vCore/mois General Purpose
    "SqlMI"      = 200.00 # USD/vCore/mois General Purpose
}

# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","SECTION")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        "INFO"    = "Cyan"
        "WARN"    = "Yellow"
        "ERROR"   = "Red"
        "SUCCESS" = "Green"
        "SECTION" = "Magenta"
    }
    $prefix = @{
        "INFO"    = "  ℹ"
        "WARN"    = "  ⚠"
        "ERROR"   = "  ✖"
        "SUCCESS" = "  ✔"
        "SECTION" = "══"
    }
    Write-Host "[$timestamp] $($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Get-VmCpuCount {
    param([object]$Vm)
    try {
        $size = $Vm.HardwareProfile.VmSize
        # Extraire le nombre de vCPUs depuis le nom du SKU (ex: Standard_D4s_v3 → 4)
        if ($size -match '_D(\d+)s?_') { return [int]$Matches[1] }
        if ($size -match '_E(\d+)s?_') { return [int]$Matches[1] }
        if ($size -match '_F(\d+)s?_') { return [int]$Matches[1] }
        if ($size -match '_B(\d+)m?s?_') { return [int]$Matches[1] }
        if ($size -match '_(\d+)') { return [int]$Matches[1] }
        return 2  # fallback conservateur
    }
    catch { return 2 }
}

function Estimate-MonthlySavings {
    param(
        [string]$ResourceType,
        [int]$vCpuCount,
        [bool]$AhbEnabled
    )
    $pricePerVCpu = $VCPU_PRICE_USD_MONTHLY[$ResourceType]
    $savingsRate  = $AHB_SAVINGS_RATE[$ResourceType]
    $totalCost    = $pricePerVCpu * $vCpuCount

    if ($AhbEnabled) {
        # Économie déjà réalisée
        return [math]::Round($totalCost * $savingsRate, 2)
    } else {
        # Économie potentielle si AHB activé
        return [math]::Round($totalCost * $savingsRate, 2)
    }
}

function Get-AhbStatusLabel {
    param([string]$LicenseType)
    switch ($LicenseType) {
        "Windows_Server" { return "ACTIVÉ" }
        "AHUB"           { return "ACTIVÉ" }
        "BasePrice"      { return "NON ACTIVÉ" }
        "LicenseIncluded"{ return "NON ACTIVÉ" }
        $null            { return "NON ACTIVÉ" }
        ""               { return "NON ACTIVÉ" }
        default          { return "NON ACTIVÉ ($LicenseType)" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────────────────────────────────────

Write-Log "═══════════════════════════════════════════════════════════════" -Level SECTION
Write-Log " AZURE HYBRID BENEFIT AUDIT v2.0.0" -Level SECTION
Write-Log " Démarré le : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level SECTION
Write-Log "═══════════════════════════════════════════════════════════════" -Level SECTION

# Vérification du répertoire de sortie
if (-not (Test-Path $OutputDir)) {
    Write-Log "Création du répertoire de sortie : $OutputDir" -Level WARN
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath        = Join-Path $OutputDir "AzHybridBenefitAudit_$timestamp.csv"
$csvSummaryPath = Join-Path $OutputDir "AzHybridBenefitAudit_${timestamp}_Summary.csv"

# Vérification de la connexion Azure
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Log "Aucun contexte Azure actif. Connexion en cours..." -Level WARN
        Connect-AzAccount | Out-Null
        $context = Get-AzContext
    }
    Write-Log "Connecté en tant que : $($context.Account.Id)" -Level SUCCESS
    Write-Log "Tenant : $($context.Tenant.Id)" -Level INFO
}
catch {
    Write-Log "Impossible de se connecter à Azure : $_" -Level ERROR
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# RÉCUPÉRATION DES SOUSCRIPTIONS
# ─────────────────────────────────────────────────────────────────────────────

Write-Log "" -Level INFO
Write-Log "Récupération des souscriptions..." -Level SECTION

[System.Collections.Generic.List[object]]$subscriptions = [System.Collections.Generic.List[object]]::new()

if ($SubscriptionIds.Count -gt 0) {
    foreach ($subId in $SubscriptionIds) {
        $sub = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
        if ($sub) {
            $subscriptions.Add($sub)
        } else {
            Write-Log "Souscription introuvable ou inaccessible : $subId" -Level WARN
        }
    }
} else {
    $allSubs = Get-AzSubscription -ErrorAction SilentlyContinue
    foreach ($sub in $allSubs) {
        $stateOk = ($sub.State -eq "Enabled")
        if ($IncludeDisabledSubscriptions -or $stateOk) {
            $subscriptions.Add($sub)
        } else {
            Write-Log "Souscription ignorée (état: $($sub.State)) : $($sub.Name)" -Level WARN
        }
    }
}

Write-Log "Souscriptions à auditer : $($subscriptions.Count)" -Level SUCCESS

if ($subscriptions.Count -eq 0) {
    Write-Log "Aucune souscription à auditer. Vérifiez vos permissions." -Level ERROR
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTE DES DONNÉES
# ─────────────────────────────────────────────────────────────────────────────

[System.Collections.Generic.List[PSCustomObject]]$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

$subIndex = 0
foreach ($sub in $subscriptions) {
    $subIndex++
    Write-Log "" -Level INFO
    Write-Log "[$subIndex/$($subscriptions.Count)] Souscription : $($sub.Name) [$($sub.Id)]" -Level SECTION

    try {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Log "Impossible de changer de contexte vers $($sub.Name) : $_" -Level ERROR
        continue
    }

    # ── 1. VMs WINDOWS SERVER ──────────────────────────────────────────────
    Write-Log "  → Scan VMs Windows Server..." -Level INFO

    try {
        $vms = Get-AzVM -ErrorAction SilentlyContinue
        if ($null -ne $vms) {
            # Guard single-object unwrapping
            [System.Collections.Generic.List[object]]$vmList = [System.Collections.Generic.List[object]]::new()
            foreach ($vm in $vms) { $vmList.Add($vm) }

            foreach ($vm in $vmList) {
                $osType      = $vm.StorageProfile.OsDisk.OsType
                $licenseType = $vm.LicenseType

                # Détection SQL Server VM (présence d'extension SqlIaas ou tag)
                $isSqlVm = $false
                $vmExtensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName `
                                                   -VMName $vm.Name `
                                                   -ErrorAction SilentlyContinue
                if ($vmExtensions) {
                    foreach ($ext in $vmExtensions) {
                        if ($ext.Publisher -like "*SqlServer*" -or $ext.ExtensionType -like "*SqlIaas*") {
                            $isSqlVm = $true
                            break
                        }
                    }
                }
                # Vérif tag SQL
                if ($vm.Tags -and ($vm.Tags.Keys -match "sql" -or $vm.Tags.Values -match "sql")) {
                    $isSqlVm = $true
                }

                # Filtrer uniquement les VMs Windows
                if ($osType -ne "Windows") { continue }

                $resourceType = if ($isSqlVm) { "SqlVM" } else { "WindowsVM" }
                $ahbEnabled   = ($licenseType -eq "Windows_Server")
                $ahbStatus    = Get-AhbStatusLabel -LicenseType $licenseType
                $vCpus        = Get-VmCpuCount -Vm $vm
                $savingsUSD   = Estimate-MonthlySavings -ResourceType $resourceType `
                                                         -vCpuCount $vCpus `
                                                         -AhbEnabled $ahbEnabled
                $savingsEUR   = [math]::Round($savingsUSD * $ExchangeRateEURUSD, 2)

                $result = [PSCustomObject]@{
                    SubscriptionId        = $sub.Id
                    SubscriptionName      = $sub.Name
                    ResourceGroup         = $vm.ResourceGroupName
                    ResourceName          = $vm.Name
                    ResourceType          = "Virtual Machine"
                    SubType               = if ($isSqlVm) { "SQL Server VM" } else { "Windows Server VM" }
                    Location              = $vm.Location
                    SKU_Size              = $vm.HardwareProfile.VmSize
                    vCPU_Estimate         = $vCpus
                    LicenseType_Raw       = if ($licenseType) { $licenseType } else { "null" }
                    AHB_Status            = $ahbStatus
                    AHB_Enabled           = $ahbEnabled
                    EconomiesRealisees_USD = if ($ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesRealisees_EUR = if ($ahbEnabled) { $savingsEUR } else { 0 }
                    EconomiesPotentielles_USD = if (-not $ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesPotentielles_EUR = if (-not $ahbEnabled) { $savingsEUR } else { 0 }
                    SavingsRatePct        = ($AHB_SAVINGS_RATE[$resourceType] * 100).ToString("F0") + "%"
                    Recommendation        = if ($ahbEnabled) {
                                               "AHB actif — économie en cours"
                                            } else {
                                               "⚡ Activer AHB → économiser ~$savingsUSD USD/mois"
                                            }
                    ResourceId            = $vm.Id
                }
                $allResults.Add($result)

                $statusIcon = if ($ahbEnabled) { "✔" } else { "○" }
                Write-Log "    $statusIcon VM: $($vm.Name) | AHB: $ahbStatus | Économie: $savingsUSD USD/mois" -Level INFO
            }
        }
    }
    catch {
        Write-Log "Erreur lors du scan des VMs : $_" -Level ERROR
    }

    # ── 2. SQL SERVER VMs (Az.SqlVirtualMachine) ───────────────────────────
    Write-Log "  → Scan SQL Virtual Machines (ressources SqlVirtualMachine)..." -Level INFO

    try {
        $sqlVms = Get-AzSqlVM -ErrorAction SilentlyContinue
        if ($null -ne $sqlVms) {
            [System.Collections.Generic.List[object]]$sqlVmList = [System.Collections.Generic.List[object]]::new()
            foreach ($sv in $sqlVms) { $sqlVmList.Add($sv) }

            foreach ($sqlVm in $sqlVmList) {
                $licenseType = $sqlVm.SqlServerLicenseType
                $ahbEnabled  = ($licenseType -eq "AHUB")
                $ahbStatus   = if ($ahbEnabled) { "ACTIVÉ" } else { "NON ACTIVÉ" }

                # vCPUs : essayer de récupérer la VM parente
                $vCpus = 4  # défaut
                $parentVm = Get-AzVM -ResourceGroupName $sqlVm.ResourceGroupName `
                                     -Name $sqlVm.Name -ErrorAction SilentlyContinue
                if ($parentVm) { $vCpus = Get-VmCpuCount -Vm $parentVm }

                $savingsUSD = Estimate-MonthlySavings -ResourceType "SqlVM" `
                                                       -vCpuCount $vCpus `
                                                       -AhbEnabled $ahbEnabled
                $savingsEUR = [math]::Round($savingsUSD * $ExchangeRateEURUSD, 2)

                # Vérifier si déjà capturé via Get-AzVM (éviter doublons)
                $alreadyAdded = $allResults | Where-Object {
                    $_.ResourceName -eq $sqlVm.Name -and
                    $_.ResourceGroup -eq $sqlVm.ResourceGroupName -and
                    $_.SubType -eq "SQL Server VM"
                }
                if ($alreadyAdded) { continue }

                $result = [PSCustomObject]@{
                    SubscriptionId        = $sub.Id
                    SubscriptionName      = $sub.Name
                    ResourceGroup         = $sqlVm.ResourceGroupName
                    ResourceName          = $sqlVm.Name
                    ResourceType          = "Virtual Machine"
                    SubType               = "SQL Server VM"
                    Location              = $sqlVm.Location
                    SKU_Size              = if ($parentVm) { $parentVm.HardwareProfile.VmSize } else { "N/A" }
                    vCPU_Estimate         = $vCpus
                    LicenseType_Raw       = if ($licenseType) { $licenseType } else { "null" }
                    AHB_Status            = $ahbStatus
                    AHB_Enabled           = $ahbEnabled
                    EconomiesRealisees_USD = if ($ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesRealisees_EUR = if ($ahbEnabled) { $savingsEUR } else { 0 }
                    EconomiesPotentielles_USD = if (-not $ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesPotentielles_EUR = if (-not $ahbEnabled) { $savingsEUR } else { 0 }
                    SavingsRatePct        = ($AHB_SAVINGS_RATE["SqlVM"] * 100).ToString("F0") + "%"
                    Recommendation        = if ($ahbEnabled) {
                                               "AHB actif — économie en cours"
                                            } else {
                                               "⚡ Activer AHB → économiser ~$savingsUSD USD/mois"
                                            }
                    ResourceId            = $sqlVm.Id
                }
                $allResults.Add($result)

                $statusIcon = if ($ahbEnabled) { "✔" } else { "○" }
                Write-Log "    $statusIcon SQL VM: $($sqlVm.Name) | AHB: $ahbStatus | Économie: $savingsUSD USD/mois" -Level INFO
            }
        }
    }
    catch {
        Write-Log "Module Az.SqlVirtualMachine non disponible ou erreur : $_" -Level WARN
    }

    # ── 3. AZURE SQL DATABASE ──────────────────────────────────────────────
    Write-Log "  → Scan Azure SQL Databases..." -Level INFO

    try {
        $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue
        if ($null -ne $sqlServers) {
            [System.Collections.Generic.List[object]]$sqlServerList = [System.Collections.Generic.List[object]]::new()
            foreach ($srv in $sqlServers) { $sqlServerList.Add($srv) }

            foreach ($sqlServer in $sqlServerList) {
                $databases = Get-AzSqlDatabase -ServerName $sqlServer.ServerName `
                                                -ResourceGroupName $sqlServer.ResourceGroupName `
                                                -ErrorAction SilentlyContinue
                if ($null -eq $databases) { continue }

                [System.Collections.Generic.List[object]]$dbList = [System.Collections.Generic.List[object]]::new()
                foreach ($db in $databases) { $dbList.Add($db) }

                foreach ($db in $dbList) {
                    # Ignorer master
                    if ($db.DatabaseName -eq "master") { continue }

                    $licenseType = $db.LicenseType
                    $ahbEnabled  = ($licenseType -eq "BasePrice")
                    $ahbStatus   = if ($ahbEnabled) { "ACTIVÉ" } else { "NON ACTIVÉ" }

                    # vCores disponibles uniquement sur le modèle vCore
                    $vCores = if ($db.Capacity -gt 0) { $db.Capacity } else { 2 }

                    $savingsUSD = Estimate-MonthlySavings -ResourceType "SqlDB" `
                                                           -vCpuCount $vCores `
                                                           -AhbEnabled $ahbEnabled
                    $savingsEUR = [math]::Round($savingsUSD * $ExchangeRateEURUSD, 2)

                    $result = [PSCustomObject]@{
                        SubscriptionId        = $sub.Id
                        SubscriptionName      = $sub.Name
                        ResourceGroup         = $db.ResourceGroupName
                        ResourceName          = "$($sqlServer.ServerName)/$($db.DatabaseName)"
                        ResourceType          = "Azure SQL Database"
                        SubType               = "SQL Database ($($db.Edition))"
                        Location              = $db.Location
                        SKU_Size              = "$($db.SkuName) $($db.Edition)"
                        vCPU_Estimate         = $vCores
                        LicenseType_Raw       = if ($licenseType) { $licenseType } else { "DTU-model (non éligible vCore)" }
                        AHB_Status            = $ahbStatus
                        AHB_Enabled           = $ahbEnabled
                        EconomiesRealisees_USD = if ($ahbEnabled) { $savingsUSD } else { 0 }
                        EconomiesRealisees_EUR = if ($ahbEnabled) { $savingsEUR } else { 0 }
                        EconomiesPotentielles_USD = if (-not $ahbEnabled) { $savingsUSD } else { 0 }
                        EconomiesPotentielles_EUR = if (-not $ahbEnabled) { $savingsEUR } else { 0 }
                        SavingsRatePct        = ($AHB_SAVINGS_RATE["SqlDB"] * 100).ToString("F0") + "%"
                        Recommendation        = if ($ahbEnabled) {
                                                   "AHB actif — économie en cours"
                                                } elseif ($null -eq $licenseType -or $licenseType -eq "") {
                                                   "ℹ Modèle DTU — passer en vCore pour activer AHB"
                                                } else {
                                                   "⚡ Activer AHB (LicenseType=BasePrice) → économiser ~$savingsUSD USD/mois"
                                                }
                        ResourceId            = $db.ResourceId
                    }
                    $allResults.Add($result)

                    $statusIcon = if ($ahbEnabled) { "✔" } else { "○" }
                    Write-Log "    $statusIcon SQL DB: $($db.DatabaseName) | AHB: $ahbStatus | Économie: $savingsUSD USD/mois" -Level INFO
                }
            }
        }
    }
    catch {
        Write-Log "Erreur lors du scan des SQL Databases : $_" -Level ERROR
    }

    # ── 4. AZURE SQL MANAGED INSTANCE ─────────────────────────────────────
    Write-Log "  → Scan Azure SQL Managed Instances..." -Level INFO

    try {
        $sqlMIs = Get-AzSqlInstance -ErrorAction SilentlyContinue
        if ($null -ne $sqlMIs) {
            [System.Collections.Generic.List[object]]$sqlMIList = [System.Collections.Generic.List[object]]::new()
            foreach ($mi in $sqlMIs) { $sqlMIList.Add($mi) }

            foreach ($mi in $sqlMIList) {
                $licenseType = $mi.LicenseType
                $ahbEnabled  = ($licenseType -eq "BasePrice")
                $ahbStatus   = if ($ahbEnabled) { "ACTIVÉ" } else { "NON ACTIVÉ" }
                $vCores      = if ($mi.VCores -gt 0) { $mi.VCores } else { 4 }

                $savingsUSD = Estimate-MonthlySavings -ResourceType "SqlMI" `
                                                       -vCpuCount $vCores `
                                                       -AhbEnabled $ahbEnabled
                $savingsEUR = [math]::Round($savingsUSD * $ExchangeRateEURUSD, 2)

                $result = [PSCustomObject]@{
                    SubscriptionId        = $sub.Id
                    SubscriptionName      = $sub.Name
                    ResourceGroup         = $mi.ResourceGroupName
                    ResourceName          = $mi.ManagedInstanceName
                    ResourceType          = "SQL Managed Instance"
                    SubType               = "SQL Managed Instance ($($mi.Sku.Name))"
                    Location              = $mi.Location
                    SKU_Size              = "$($mi.Sku.Name) $($mi.Sku.Tier)"
                    vCPU_Estimate         = $vCores
                    LicenseType_Raw       = if ($licenseType) { $licenseType } else { "null" }
                    AHB_Status            = $ahbStatus
                    AHB_Enabled           = $ahbEnabled
                    EconomiesRealisees_USD = if ($ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesRealisees_EUR = if ($ahbEnabled) { $savingsEUR } else { 0 }
                    EconomiesPotentielles_USD = if (-not $ahbEnabled) { $savingsUSD } else { 0 }
                    EconomiesPotentielles_EUR = if (-not $ahbEnabled) { $savingsEUR } else { 0 }
                    SavingsRatePct        = ($AHB_SAVINGS_RATE["SqlMI"] * 100).ToString("F0") + "%"
                    Recommendation        = if ($ahbEnabled) {
                                               "AHB actif — économie en cours"
                                            } else {
                                               "⚡ Activer AHB (LicenseType=BasePrice) → économiser ~$savingsUSD USD/mois"
                                            }
                    ResourceId            = $mi.Id
                }
                $allResults.Add($result)

                $statusIcon = if ($ahbEnabled) { "✔" } else { "○" }
                Write-Log "    $statusIcon SQL MI: $($mi.ManagedInstanceName) | AHB: $ahbStatus | Économie: $savingsUSD USD/mois" -Level INFO
            }
        }
    }
    catch {
        Write-Log "Erreur lors du scan des SQL Managed Instances : $_" -Level ERROR
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# EXPORT CSV DÉTAILLÉ
# ─────────────────────────────────────────────────────────────────────────────

Write-Log "" -Level INFO
Write-Log "Export des résultats..." -Level SECTION

if ($allResults.Count -eq 0) {
    Write-Log "Aucune ressource éligible AHB trouvée." -Level WARN
} else {
    # CSV détaillé
    $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Log "CSV détaillé exporté : $csvPath ($($allResults.Count) ressources)" -Level SUCCESS

    # ── CALCUL DU RÉSUMÉ ─────────────────────────────────────────────────
    $totalRealisedUSD    = 0.0
    $totalRealisedEUR    = 0.0
    $totalPotentialUSD   = 0.0
    $totalPotentialEUR   = 0.0
    $countAhbActive      = 0
    $countAhbInactive    = 0

    foreach ($r in $allResults) {
        $totalRealisedUSD  += $r.EconomiesRealisees_USD
        $totalRealisedEUR  += $r.EconomiesRealisees_EUR
        $totalPotentialUSD += $r.EconomiesPotentielles_USD
        $totalPotentialEUR += $r.EconomiesPotentielles_EUR
        if ($r.AHB_Enabled) { $countAhbActive++ } else { $countAhbInactive++ }
    }

    # Résumé par souscription
    [System.Collections.Generic.List[PSCustomObject]]$summaryRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Groupement manuel par SubscriptionName (éviter pipeline single-object issue)
    [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]$subGroups = `
        [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new()

    foreach ($r in $allResults) {
        $key = $r.SubscriptionName
        if (-not $subGroups.ContainsKey($key)) {
            $subGroups[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $subGroups[$key].Add($r)
    }

    foreach ($key in $subGroups.Keys) {
        $items = $subGroups[$key]
        $subRealUSD = 0.0
        $subRealEUR = 0.0
        $subPotUSD  = 0.0
        $subPotEUR  = 0.0
        $subActive  = 0
        $subInactive = 0

        foreach ($item in $items) {
            $subRealUSD  += $item.EconomiesRealisees_USD
            $subRealEUR  += $item.EconomiesRealisees_EUR
            $subPotUSD   += $item.EconomiesPotentielles_USD
            $subPotEUR   += $item.EconomiesPotentielles_EUR
            if ($item.AHB_Enabled) { $subActive++ } else { $subInactive++ }
        }

        $summaryRows.Add([PSCustomObject]@{
            SubscriptionName               = $key
            SubscriptionId                 = $items[0].SubscriptionId
            TotalRessourcesEligibles       = $items.Count
            RessourcesAvecAHB_Actif        = $subActive
            RessourcesSansAHB              = $subInactive
            EconomiesRealisees_USD_Mensuel = [math]::Round($subRealUSD, 2)
            EconomiesRealisees_EUR_Mensuel = [math]::Round($subRealEUR, 2)
            EconomiesRealisees_USD_Annuel  = [math]::Round($subRealUSD * 12, 2)
            EconomiesRealisees_EUR_Annuel  = [math]::Round($subRealEUR * 12, 2)
            EconomiesPotentielles_USD_Mensuel = [math]::Round($subPotUSD, 2)
            EconomiesPotentielles_EUR_Mensuel = [math]::Round($subPotEUR, 2)
            EconomiesPotentielles_USD_Annuel  = [math]::Round($subPotUSD * 12, 2)
            EconomiesPotentielles_EUR_Annuel  = [math]::Round($subPotEUR * 12, 2)
            TotalCombined_USD_Annuel       = [math]::Round(($subRealUSD + $subPotUSD) * 12, 2)
        })
    }

    # Ligne TOTAL
    $summaryRows.Add([PSCustomObject]@{
        SubscriptionName               = "=== TOTAL TENANT ==="
        SubscriptionId                 = ""
        TotalRessourcesEligibles       = $allResults.Count
        RessourcesAvecAHB_Actif        = $countAhbActive
        RessourcesSansAHB              = $countAhbInactive
        EconomiesRealisees_USD_Mensuel = [math]::Round($totalRealisedUSD, 2)
        EconomiesRealisees_EUR_Mensuel = [math]::Round($totalRealisedEUR, 2)
        EconomiesRealisees_USD_Annuel  = [math]::Round($totalRealisedUSD * 12, 2)
        EconomiesRealisees_EUR_Annuel  = [math]::Round($totalRealisedEUR * 12, 2)
        EconomiesPotentielles_USD_Mensuel = [math]::Round($totalPotentialUSD, 2)
        EconomiesPotentielles_EUR_Mensuel = [math]::Round($totalPotentialEUR, 2)
        EconomiesPotentielles_USD_Annuel  = [math]::Round($totalPotentialUSD * 12, 2)
        EconomiesPotentielles_EUR_Annuel  = [math]::Round($totalPotentialEUR * 12, 2)
        TotalCombined_USD_Annuel       = [math]::Round(($totalRealisedUSD + $totalPotentialUSD) * 12, 2)
    })

    $summaryRows | Export-Csv -Path $csvSummaryPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Log "CSV résumé exporté : $csvSummaryPath" -Level SUCCESS

    # ── AFFICHAGE CONSOLE DU RÉSUMÉ ───────────────────────────────────────
    Write-Log "" -Level INFO
    Write-Log "═══════════════════════════════════════════════════════════════" -Level SECTION
    Write-Log " RÉSUMÉ GLOBAL DU TENANT" -Level SECTION
    Write-Log "═══════════════════════════════════════════════════════════════" -Level SECTION
    Write-Log "  Ressources éligibles AHB scannées   : $($allResults.Count)" -Level INFO
    Write-Log "  Ressources avec AHB ACTIF            : $countAhbActive" -Level SUCCESS
    Write-Log "  Ressources sans AHB (opportunités)   : $countAhbInactive" -Level WARN
    Write-Log "" -Level INFO
    Write-Log "  ÉCONOMIES RÉALISÉES (AHB actif)" -Level SUCCESS
    Write-Log "    Mensuel  : $([math]::Round($totalRealisedUSD,2)) USD  |  $([math]::Round($totalRealisedEUR,2)) EUR" -Level SUCCESS
    Write-Log "    Annuel   : $([math]::Round($totalRealisedUSD*12,2)) USD  |  $([math]::Round($totalRealisedEUR*12,2)) EUR" -Level SUCCESS
    Write-Log "" -Level INFO
    Write-Log "  ÉCONOMIES POTENTIELLES (AHB non activé)" -Level WARN
    Write-Log "    Mensuel  : $([math]::Round($totalPotentialUSD,2)) USD  |  $([math]::Round($totalPotentialEUR,2)) EUR" -Level WARN
    Write-Log "    Annuel   : $([math]::Round($totalPotentialUSD*12,2)) USD  |  $([math]::Round($totalPotentialEUR*12,2)) EUR" -Level WARN
    Write-Log "" -Level INFO
    Write-Log "  TOTAL COMBINÉ (réalisé + potentiel) ANNUEL" -Level SECTION
    Write-Log "    $([math]::Round(($totalRealisedUSD+$totalPotentialUSD)*12,2)) USD  |  $([math]::Round(($totalRealisedEUR+$totalPotentialEUR)*12,2)) EUR" -Level SECTION
    Write-Log "═══════════════════════════════════════════════════════════════" -Level SECTION
    Write-Log "" -Level INFO
    Write-Log "  ⚠  AVERTISSEMENT : Les montants sont des ESTIMATIONS basées sur" -Level WARN
    Write-Log "     des ratios documentés Microsoft. Utilisez le Azure Pricing Calculator" -Level WARN
    Write-Log "     avec vos SKUs et régions exacts pour des chiffres précis." -Level WARN
    Write-Log "" -Level INFO
    Write-Log "Fichiers générés :" -Level SUCCESS
    Write-Log "  📄 Détail  : $csvPath" -Level INFO
    Write-Log "  📊 Résumé  : $csvSummaryPath" -Level INFO
    Write-Log "" -Level INFO
    Write-Log "Audit terminé le : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level SUCCESS
}
