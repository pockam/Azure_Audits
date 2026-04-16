<#
.SYNOPSIS
    Audit RBAC complet - Analyse par etendue initiale d'attribution sur le Root Management Group.
.DESCRIPTION
    - Parcourt toutes les souscriptions du root management group
    - Detecte les attributions directes aux utilisateurs
    - Identifie les groupes avec nomenclature incoherente avec leur role
    - Gere les DisplayName vides/null
    - Statistiques par etendue INITIALE (heritage resolu)
    - Dashboard HTML avec onglets par etendue fautive
    - Export CSV consolide + JSON ITSM-ready
.PARAMETER OutputDirectory
    Repertoire de sortie. Defaut : repertoire courant.
.PARAMETER RootManagementGroupId
    ID du Root MG. Auto-detecte si non fourni.
.PARAMETER SkipLogin
    Passe la connexion interactive.
.NOTES
    Version : 3.0.0 — Fix definitif dewrapping PowerShell
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory       = (Get-Location).Path,
    [string]$RootManagementGroupId = "",
    [switch]$SkipLogin
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── CONSTANTES ─────────────────────────────────────────────────────────

$TIMESTAMP   = Get-Date -Format "yyyyMMdd_HHmmss"
$REPORT_DATE = Get-Date -Format "dd/MM/yyyy a HH:mm:ss"
$HTML_PATH   = Join-Path $OutputDirectory "RBAC_Audit_$TIMESTAMP.html"
$CSV_PATH    = Join-Path $OutputDirectory "RBAC_Audit_$TIMESTAMP.csv"
$JSON_PATH   = Join-Path $OutputDirectory "RBAC_NonCompliance_ITSM_$TIMESTAMP.json"

$ROLE_PATTERNS = [ordered]@{
    "Owner"                       = @("owner","proprio","proprietaire","owners")
    "Contributor"                 = @("contributor","contrib","contributeur","contributors")
    "Reader"                      = @("reader","readers","lecteur","lecture","readonly","read-only")
    "User Access Administrator"   = @("useraccess","uaa","accessadmin","iam","identityadmin")
    "Network Contributor"         = @("network","netcontrib","reseau","net-")
    "Storage Account Contributor" = @("storage","storagecontrib","blob","stockage")
    "Virtual Machine Contributor" = @("vm","vmcontrib","virtualmachine","compute")
    "Security Admin"              = @("security","secadmin","securite","secops")
    "Monitoring Contributor"      = @("monitor","monitoring","observability","logs")
    "Key Vault Administrator"     = @("keyvault","kv","secrets","vault")
}

#endregion

#region ── LOGGING ────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS","DEBUG")]
        [string]$Level = "INFO"
    )
    $ts  = Get-Date -Format "HH:mm:ss"
    $col = @{ INFO="Cyan"; WARN="Yellow"; ERROR="Red"; SUCCESS="Green"; DEBUG="Gray" }
    $pfx = @{ INFO="  i"; WARN="  !"; ERROR="  X"; SUCCESS="  v"; DEBUG="  ." }
    Write-Host "[$ts] $($pfx[$Level]) $Message" -ForegroundColor $col[$Level]
}

#endregion

#region ── FONCTIONS UTILITAIRES ──────────────────────────────────────────────

function Resolve-ScopeInfo {
    param([string]$Scope)
    $r = [PSCustomObject]@{ ScopeType="Unknown"; ScopeId=$Scope; ScopeName=$Scope; ScopeShort=$Scope }
    if      ($Scope -match "^/providers/Microsoft\.Management/managementGroups/([^/]+)$") {
        $r.ScopeType="ManagementGroup"; $r.ScopeId=$Matches[1]; $r.ScopeName="MG: $($Matches[1])"; $r.ScopeShort="MG/$($Matches[1])"
    }
    elseif  ($Scope -match "^/subscriptions/([^/]+)$") {
        $r.ScopeType="Subscription"; $r.ScopeId=$Matches[1]; $r.ScopeName="SUB: $($Matches[1])"; $r.ScopeShort="SUB/$($Matches[1])"
    }
    elseif  ($Scope -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)$") {
        $r.ScopeType="ResourceGroup"; $r.ScopeId="$($Matches[1])/$($Matches[2])"; $r.ScopeName="RG: $($Matches[2])"; $r.ScopeShort="RG/$($Matches[2])"
    }
    elseif  ($Scope -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/.+") {
        $parts=$Scope -split "/"; $r.ScopeType="Resource"; $r.ScopeId=$Scope; $r.ScopeName="RES: $($parts[-1])"; $r.ScopeShort="RES/$($parts[-1])"
    }
    return $r
}

function Test-GroupNamingMismatch {
    param([string]$GroupName, [string]$AssignedRole)
    $low = $GroupName.ToLower()
    foreach ($role in $ROLE_PATTERNS.Keys) {
        foreach ($pat in $ROLE_PATTERNS[$role]) {
            if ($low -match [regex]::Escape($pat)) {
                if ($AssignedRole -ne $role) { return [PSCustomObject]@{ IsMismatch=$true;  DetectedRole=$role } }
                return                         [PSCustomObject]@{ IsMismatch=$false; DetectedRole="" }
            }
        }
    }
    return [PSCustomObject]@{ IsMismatch=$false; DetectedRole="" }
}

# Compte les elements d'une liste generique de facon sure (pas de dewrapping)
function Get-SafeCount {
    param($Collection)
    if ($null -eq $Collection) { return 0 }
    if ($Collection -is [System.Collections.ICollection]) { return $Collection.Count }
    # Objet unique (dewrappe par PowerShell) : compte = 1
    return 1
}

# Filtre une liste generique et retourne le nombre de matches (safe)
function Get-FilteredCount {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$List,
        [string]$Property,
        [string]$Value
    )
    $n = 0
    foreach ($item in $List) {
        if ($item.$Property -eq $Value) { $n++ }
    }
    return $n
}

function Build-AnomalyTableRows {
    param([System.Collections.Generic.List[PSCustomObject]]$Anomalies)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($row in $Anomalies) {
        $typeClass  = if ($row.AnomalyType -eq "DirectUserAssignment") { "badge-danger" } else { "badge-warning" }
        $typeLabel  = if ($row.AnomalyType -eq "DirectUserAssignment") { "Utilisateur Direct" } else { "Nomenclature KO" }
        $sevClass   = if ($row.AnomalySeverity -eq "High") { "badge-danger" } else { "badge-warning" }
        $scopeClass = switch ($row.ScopeType) {
            "ManagementGroup" { "badge-purple" }
            "Subscription"    { "badge-info"   }
            "ResourceGroup"   { "badge-teal"   }
            "Resource"        { "badge-gray"   }
            default           { "badge-gray"   }
        }
        $dn   = [System.Web.HttpUtility]::HtmlEncode($row.DisplayName)
        $si   = [System.Web.HttpUtility]::HtmlEncode($row.SignInName)
        $sn   = [System.Web.HttpUtility]::HtmlEncode($row.ScopeName)
        $sf   = [System.Web.HttpUtility]::HtmlEncode($row.Scope)
        $sub  = [System.Web.HttpUtility]::HtmlEncode($row.SubscriptionName)
        $role = [System.Web.HttpUtility]::HtmlEncode($row.AssignedRole)
        $exp  = [System.Web.HttpUtility]::HtmlEncode($row.ExpectedRole)
        $desc = [System.Web.HttpUtility]::HtmlEncode($row.Description)
        $expCell = if ($row.ExpectedRole -ne "N/A") { "<span class='badge badge-info'>$exp</span>" } else { "&mdash;" }
        $null = $sb.AppendLine("<tr><td><span class='badge $typeClass'>$typeLabel</span></td><td><span class='badge $sevClass'>$($row.AnomalySeverity)</span></td><td><span class='badge $scopeClass'>$($row.ScopeType)</span></td><td class='scope-cell' title='$sf'>$sn</td><td><strong>$dn</strong><br><small class='signin'>$si</small></td><td>$sub</td><td><span class='badge badge-role'>$role</span></td><td>$expCell</td><td class='desc-cell' title='$desc'>$desc</td></tr>")
    }
    return $sb.ToString()
}

#endregion

#region ── CONNEXION ──────────────────────────────────────────────────────────

if (-not $SkipLogin) {
    Write-Log "Connexion a Azure..." "INFO"
    try   { Connect-AzAccount -UseDeviceAuthentication; Write-Log "Connecte." "SUCCESS" }
    catch { Write-Log "Erreur connexion : $_" "ERROR"; exit 1 }
}

#endregion

#region ── ROOT MANAGEMENT GROUP ──────────────────────────────────────────────

Write-Log "Resolution du Root Management Group..." "INFO"
if ([string]::IsNullOrWhiteSpace($RootManagementGroupId)) {
    try {
        $tenantId = (Get-AzContext).Tenant.Id
        $allMGs   = @(Get-AzManagementGroup -ErrorAction Stop)
        $rootMG   = $allMGs | Where-Object { $_.Name -eq $tenantId } | Select-Object -First 1
        if (-not $rootMG) { $rootMG = $allMGs | Select-Object -First 1; Write-Log "Root MG auto : $($rootMG.DisplayName)" "WARN" }
        $RootManagementGroupId = $rootMG.Name
    }
    catch { Write-Log "Impossible de resoudre le Root MG : $_" "ERROR"; exit 1 }
}
Write-Log "Root MG : $RootManagementGroupId" "SUCCESS"

#endregion

#region ── SOUSCRIPTIONS ──────────────────────────────────────────────────────

Write-Log "Recuperation des souscriptions actives..." "INFO"
try {
    [System.Collections.Generic.List[object]]$allSubscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" })
    Write-Log "$($allSubscriptions.Count) souscription(s) trouvee(s)." "SUCCESS"
}
catch { Write-Log "Erreur recuperation souscriptions : $_" "ERROR"; exit 1 }

$subNameMap = @{}
foreach ($sub in $allSubscriptions) { $subNameMap[$sub.Id] = $sub.Name }

#endregion

#region ── COLLECTE DES ROLE ASSIGNMENTS ──────────────────────────────────────

Write-Log "=================================================" "INFO"
Write-Log " PHASE 1 : Collecte et analyse RBAC" "INFO"
Write-Log "=================================================" "INFO"

# IMPORTANT : on utilise un Dictionary<string, List<PSCustomObject>> type-safe
# pour eviter tout dewrapping lors de la recuperation des valeurs
$anomaliesByScope = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSCustomObject]]]::new()

$allAnomalies       = [System.Collections.Generic.List[PSCustomObject]]::new()
$skippedAssignments = [System.Collections.Generic.List[PSCustomObject]]::new()

$globalStats = [PSCustomObject]@{
    TotalSubscriptions = $allSubscriptions.Count
    TotalAssignments   = 0
    TotalUsers         = 0
    TotalGroups        = 0
    TotalSPs           = 0
    TotalAnomalies     = 0
    TotalSkipped       = 0
    DirectUsers        = 0
    MismatchedGroups   = 0
}

$subIndex = 0

foreach ($sub in $allSubscriptions) {
    $subIndex++
    Write-Log "[$subIndex/$($allSubscriptions.Count)] $($sub.Name)" "INFO"

    try   { Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null }
    catch { Write-Log "  Impossible de basculer : $_" "ERROR"; continue }

    [System.Collections.Generic.List[object]]$assignments = [System.Collections.Generic.List[object]]::new()
    try {
        $raw = Get-AzRoleAssignment -ErrorAction Stop
        # Forcer en liste meme si 0 ou 1 resultat
        if ($null -ne $raw) {
            if ($raw -is [System.Collections.IEnumerable] -and -not ($raw -is [string])) {
                foreach ($item in $raw) { $assignments.Add($item) | Out-Null }
            } else {
                $assignments.Add($raw) | Out-Null
            }
        }
        $globalStats.TotalAssignments += $assignments.Count
    }
    catch { Write-Log "  Erreur Get-AzRoleAssignment : $_" "ERROR"; continue }

    $subAnomalyCount = 0

    foreach ($assignment in $assignments) {
        switch ($assignment.ObjectType) {
            "User"             { $globalStats.TotalUsers++ }
            "Group"            { $globalStats.TotalGroups++ }
            "ServicePrincipal" { $globalStats.TotalSPs++ }
        }

        if ([string]::IsNullOrWhiteSpace($assignment.DisplayName)) {
            $globalStats.TotalSkipped++
            $skippedAssignments.Add([PSCustomObject]@{
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                ObjectId         = $assignment.ObjectId
                ObjectType       = $assignment.ObjectType
                Role             = $assignment.RoleDefinitionName
                Scope            = $assignment.Scope
                Reason           = "DisplayName vide ou null"
            }) | Out-Null
            continue
        }

        $scopeInfo = Resolve-ScopeInfo -Scope $assignment.Scope

        # Enrichissement nom de scope
        if ($scopeInfo.ScopeType -eq "Subscription") {
            $n = $subNameMap[$scopeInfo.ScopeId]
            if ($n) { $scopeInfo.ScopeName = "SUB: $n"; $scopeInfo.ScopeShort = "SUB/$n" }
        }
        elseif ($scopeInfo.ScopeType -eq "ResourceGroup") {
            if ($assignment.Scope -match "^/subscriptions/([^/]+)/resourceGroups/([^/]+)") {
                $pn = $subNameMap[$Matches[1]]
                if ($pn) { $scopeInfo.ScopeName = "RG: $($Matches[2]) ($pn)"; $scopeInfo.ScopeShort = "RG/$($Matches[2])" }
            }
        }
        elseif ($scopeInfo.ScopeType -eq "Resource") {
            if ($assignment.Scope -match "^/subscriptions/([^/]+)/") {
                $pn = $subNameMap[$Matches[1]]
                if ($pn) {
                    $parts = $assignment.Scope -split "/"
                    $scopeInfo.ScopeName  = "RES: $($parts[-1]) ($pn)"
                    $scopeInfo.ScopeShort = "RES/$($parts[-1])"
                }
            }
        }

        $anomaly = $null

        if ($assignment.ObjectType -eq "User") {
            $globalStats.DirectUsers++
            $signIn = if (-not [string]::IsNullOrWhiteSpace($assignment.SignInName)) { $assignment.SignInName } else { "N/A" }
            $anomaly = [PSCustomObject]@{
                AnomalyType      = "DirectUserAssignment"
                AnomalySeverity  = "High"
                SubscriptionName = $sub.Name
                SubscriptionId   = $sub.Id
                DisplayName      = $assignment.DisplayName
                SignInName       = $signIn
                ObjectType       = $assignment.ObjectType
                ObjectId         = $assignment.ObjectId
                AssignedRole     = $assignment.RoleDefinitionName
                ExpectedRole     = "N/A"
                Scope            = $assignment.Scope
                ScopeType        = $scopeInfo.ScopeType
                ScopeName        = $scopeInfo.ScopeName
                ScopeShort       = $scopeInfo.ScopeShort
                Description      = "Role '$($assignment.RoleDefinitionName)' attribue directement a '$($assignment.DisplayName)'. Utiliser un groupe AD."
            }
        }
        elseif ($assignment.ObjectType -eq "Group") {
            $mm = Test-GroupNamingMismatch -GroupName $assignment.DisplayName -AssignedRole $assignment.RoleDefinitionName
            if ($mm.IsMismatch) {
                $globalStats.MismatchedGroups++
                $anomaly = [PSCustomObject]@{
                    AnomalyType      = "GroupNamingMismatch"
                    AnomalySeverity  = "Medium"
                    SubscriptionName = $sub.Name
                    SubscriptionId   = $sub.Id
                    DisplayName      = $assignment.DisplayName
                    SignInName       = "N/A"
                    ObjectType       = $assignment.ObjectType
                    ObjectId         = $assignment.ObjectId
                    AssignedRole     = $assignment.RoleDefinitionName
                    ExpectedRole     = $mm.DetectedRole
                    Scope            = $assignment.Scope
                    ScopeType        = $scopeInfo.ScopeType
                    ScopeName        = $scopeInfo.ScopeName
                    ScopeShort       = $scopeInfo.ScopeShort
                    Description      = "Groupe '$($assignment.DisplayName)' suggere '$($mm.DetectedRole)' mais role attribue : '$($assignment.RoleDefinitionName)'."
                }
            }
        }

        if ($null -ne $anomaly) {
            $globalStats.TotalAnomalies++
            $subAnomalyCount++
            $allAnomalies.Add($anomaly) | Out-Null

            $key = $scopeInfo.ScopeShort
            if (-not $anomaliesByScope.ContainsKey($key)) {
                $anomaliesByScope[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $anomaliesByScope[$key].Add($anomaly) | Out-Null
        }
    }

    Write-Log "  $($assignments.Count) assignments | $subAnomalyCount anomalie(s)" "SUCCESS"
}

Write-Log "=================================================" "INFO"
Write-Log " Collecte terminee — $($globalStats.TotalAnomalies) anomalie(s) detectee(s)" $(if ($globalStats.TotalAnomalies -gt 0) {"WARN"} else {"SUCCESS"})
Write-Log "   Utilisateurs directs : $($globalStats.DirectUsers)" "INFO"
Write-Log "   Nomenclature KO      : $($globalStats.MismatchedGroups)" "INFO"
Write-Log "   Ignorees (null)      : $($globalStats.TotalSkipped)" "INFO"
Write-Log "   Etendues fautives    : $($anomaliesByScope.Count)" "INFO"
Write-Log "=================================================" "INFO"

#endregion

#region ── EXPORT CSV ─────────────────────────────────────────────────────────

Write-Log "Generation du CSV..." "INFO"

$csvRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($a in $allAnomalies) {
    $csvRows.Add([PSCustomObject]@{
        AnomalyType=      $a.AnomalyType;      AnomalySeverity=$a.AnomalySeverity
        ScopeType=        $a.ScopeType;         ScopeName=$a.ScopeName
        SubscriptionName= $a.SubscriptionName;  SubscriptionId=$a.SubscriptionId
        DisplayName=      $a.DisplayName;        SignInName=$a.SignInName
        ObjectType=       $a.ObjectType;         ObjectId=$a.ObjectId
        AssignedRole=     $a.AssignedRole;       ExpectedRole=$a.ExpectedRole
        Scope=            $a.Scope;              Description=$a.Description
    }) | Out-Null
}
foreach ($s in $skippedAssignments) {
    $csvRows.Add([PSCustomObject]@{
        AnomalyType="SkippedAssignment"; AnomalySeverity="Low"; ScopeType="Unknown"; ScopeName="N/A"
        SubscriptionName=$s.SubscriptionName; SubscriptionId=$s.SubscriptionId
        DisplayName="N/A"; SignInName="N/A"; ObjectType=$s.ObjectType; ObjectId=$s.ObjectId
        AssignedRole=$s.Role; ExpectedRole="N/A"; Scope=$s.Scope; Description=$s.Reason
    }) | Out-Null
}

$csvRows | Export-Csv -Path $CSV_PATH -NoTypeInformation -Encoding UTF8 -Force
Write-Log "CSV : $CSV_PATH ($($csvRows.Count) lignes)" "SUCCESS"

#endregion

#region ── EXPORT JSON ITSM ───────────────────────────────────────────────────

Write-Log "Generation du JSON ITSM..." "INFO"

# Repartition par scope type (foreach - pas de pipeline/.Count)
$byScopeTypeList = [System.Collections.Generic.List[PSCustomObject]]::new()
$stMap = @{}
foreach ($a in $allAnomalies) {
    if (-not $stMap.ContainsKey($a.ScopeType)) { $stMap[$a.ScopeType] = 0 }
    $stMap[$a.ScopeType]++
}
foreach ($st in $stMap.Keys) {
    $byScopeTypeList.Add([PSCustomObject]@{ scope_type=$st; count=$stMap[$st] }) | Out-Null
}

# Comptage severite par foreach (pas de Where-Object/.Count)
$highCount = 0; $medCount = 0
foreach ($a in $allAnomalies) {
    if ($a.AnomalySeverity -eq "High")   { $highCount++ }
    if ($a.AnomalySeverity -eq "Medium") { $medCount++ }
}

# Construction incidents par foreach
$incidents = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($anomaly in $allAnomalies) {
    $priority = switch ($anomaly.AnomalySeverity) { "High"{"P2"} "Medium"{"P3"} default{"P4"} }
    $remediation = switch ($anomaly.AnomalyType) {
        "DirectUserAssignment" { "Creer un groupe AD pour le role '$($anomaly.AssignedRole)'. Supprimer l'attribution directe de '$($anomaly.DisplayName)'." }
        "GroupNamingMismatch"  { "Renommer '$($anomaly.DisplayName)' pour refleter '$($anomaly.AssignedRole)', ou corriger le role vers '$($anomaly.ExpectedRole)'." }
        default                { "Verifier manuellement cette attribution RBAC." }
    }
    $incidents.Add([PSCustomObject]@{
        incident_id       = [System.Guid]::NewGuid().ToString()
        created_at        = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        status            = "Open"
        priority          = $priority
        category          = "Security"
        subcategory       = "IAM / RBAC"
        anomaly_type      = $anomaly.AnomalyType
        severity          = $anomaly.AnomalySeverity
        short_description = $anomaly.Description
        affected_resource = [PSCustomObject]@{
            scope=$anomaly.Scope; scope_type=$anomaly.ScopeType; scope_name=$anomaly.ScopeName
            subscription_id=$anomaly.SubscriptionId; subscription=$anomaly.SubscriptionName
        }
        principal = [PSCustomObject]@{
            object_id=$anomaly.ObjectId; object_type=$anomaly.ObjectType
            display_name=$anomaly.DisplayName; sign_in_name=$anomaly.SignInName
        }
        role        = [PSCustomObject]@{ assigned=$anomaly.AssignedRole; expected=$anomaly.ExpectedRole }
        remediation = $remediation
    }) | Out-Null
}

$skippedJson = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($skip in $skippedAssignments) {
    $skippedJson.Add([PSCustomObject]@{
        object_id=$skip.ObjectId; object_type=$skip.ObjectType; role=$skip.Role
        scope=$skip.Scope; sub=$skip.SubscriptionName; reason=$skip.Reason
    }) | Out-Null
}

$itsmPayload = [PSCustomObject]@{
    metadata = [PSCustomObject]@{
        report_type="RBAC_NonCompliance_Audit"; generated_at=(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        tenant_id=(Get-AzContext).Tenant.Id; root_mg_id=$RootManagementGroupId
        total_subs=$globalStats.TotalSubscriptions; total_assignments=$globalStats.TotalAssignments
        total_anomalies=$globalStats.TotalAnomalies; schema_version="3.0.0"
    }
    summary = [PSCustomObject]@{
        by_severity   = [PSCustomObject]@{ High=$highCount; Medium=$medCount; Low=$skippedAssignments.Count }
        by_type       = [PSCustomObject]@{ DirectUserAssignment=$globalStats.DirectUsers; GroupNamingMismatch=$globalStats.MismatchedGroups; SkippedAssignment=$globalStats.TotalSkipped }
        by_scope_type = $byScopeTypeList
    }
    incidents = $incidents
    skipped   = $skippedJson
}

$itsmPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $JSON_PATH -Encoding UTF8 -Force
Write-Log "JSON ITSM : $JSON_PATH ($($incidents.Count) incidents)" "SUCCESS"

#endregion

#region ── DASHBOARD HTML ─────────────────────────────────────────────────────

Write-Log "Generation du dashboard HTML..." "INFO"

# Tri des cles via une liste (pas de pipeline/.Count)
$scopeKeysList = [System.Collections.Generic.List[string]]::new()
foreach ($k in $anomaliesByScope.Keys) { $scopeKeysList.Add($k) | Out-Null }
$scopeKeysSorted = @($scopeKeysList | Sort-Object)
$scopeTabCount   = $scopeKeysSorted.Count   # int direct, pas de .Count sur pipeline

$tenantIdHtml = [System.Web.HttpUtility]::HtmlEncode((Get-AzContext).Tenant.Id)

$scopeIconMap = @{ ManagementGroup="MG"; Subscription="SUB"; ResourceGroup="RG"; Resource="RES"; Unknown="?" }

$tabButtons  = [System.Text.StringBuilder]::new()
$tabContents = [System.Text.StringBuilder]::new()

$null = $tabButtons.AppendLine('<button class="tab active" onclick="showTab(''global'')">Dashboard Global</button>')

foreach ($scopeKey in $scopeKeysSorted) {

    # Recuperation DIRECTE depuis le Dictionary type-safe : retourne toujours une List<PSCustomObject>
    $scopeList = $anomaliesByScope[$scopeKey]   # Dictionary<K,V> retourne toujours le type V exact
    $listCount = $scopeList.Count               # .Count sur Generic.List : toujours disponible

    $firstItem   = $scopeList[0]
    $tabId       = "scope-" + ($scopeKey -replace '[^a-zA-Z0-9]', '_')
    $typeLabel   = $scopeIconMap[$firstItem.ScopeType]
    $safeKey     = [System.Web.HttpUtility]::HtmlEncode($scopeKey)

    # Comptage par foreach — ZERO pipeline, ZERO .Count sur pipeline
    $highC=0; $medC=0; $dirC=0; $misC=0
    foreach ($item in $scopeList) {
        if ($item.AnomalySeverity -eq "High")                 { $highC++ }
        if ($item.AnomalySeverity -eq "Medium")               { $medC++  }
        if ($item.AnomalyType -eq "DirectUserAssignment")     { $dirC++  }
        if ($item.AnomalyType -eq "GroupNamingMismatch")      { $misC++  }
    }

    $null = $tabButtons.AppendLine("<button class=`"tab`" onclick=`"showTab('$tabId')`">[$typeLabel] $safeKey <span class='tab-badge'>$listCount</span></button>")

    $rows          = Build-AnomalyTableRows -Anomalies $scopeList
    $safeScopeName = [System.Web.HttpUtility]::HtmlEncode($firstItem.ScopeName)
    $safeScopePath = [System.Web.HttpUtility]::HtmlEncode($firstItem.Scope)

    $null = $tabContents.AppendLine(@"
<div id="$tabId" class="tab-content">
<div class="stats-mini">
  <div class="stat-mini s-orange"><div class="stat-mini-label">Anomalies</div><div class="stat-mini-num">$listCount</div></div>
  <div class="stat-mini s-red"><div class="stat-mini-label">High</div><div class="stat-mini-num">$highC</div></div>
  <div class="stat-mini s-amber"><div class="stat-mini-label">Medium</div><div class="stat-mini-num">$medC</div></div>
  <div class="stat-mini s-blue"><div class="stat-mini-label">Utilisateurs directs</div><div class="stat-mini-num">$dirC</div></div>
  <div class="stat-mini s-teal"><div class="stat-mini-label">Nomenclature KO</div><div class="stat-mini-num">$misC</div></div>
</div>
<div class="content">
  <button class="back-btn" onclick="showTab('global')">&larr; Vue Globale</button>
  <div class="scope-header">
    <span class="badge badge-scope-type">$($firstItem.ScopeType)</span>
    <h2 class="scope-title">$safeScopeName</h2>
    <p class="scope-path">$safeScopePath</p>
  </div>
  <div class="filter-box"><input type="text" id="filter-$tabId" placeholder="Filtrer..." oninput="filterTable('tbl-$tabId','filter-$tabId')"></div>
  <table id="tbl-$tabId">
    <thead><tr><th>Type</th><th>Severite</th><th>Scope</th><th>Etendue</th><th>Principal</th><th>Souscription</th><th>Role attribue</th><th>Role attendu</th><th>Description</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
</div>
</div>
"@)
}

# Tableau repartition par type de scope (foreach — pas de pipeline/.Count)
$scopeTypeRows = [System.Text.StringBuilder]::new()
$totalAno = $globalStats.TotalAnomalies
foreach ($st in $stMap.Keys | Sort-Object { $stMap[$_] } -Descending) {
    $c   = $stMap[$st]
    $pct = if ($totalAno -gt 0) { [math]::Round(($c / $totalAno) * 100, 1) } else { 0 }
    $null = $scopeTypeRows.AppendLine("<tr><td>$st</td><td><strong>$c</strong></td><td><div class='progress-bar'><div class='progress-fill' style='width:$pct%'></div></div> $pct%</td></tr>")
}

# Bloc tableau global
$globalRows = Build-AnomalyTableRows -Anomalies $allAnomalies
$globalTableBlock = if ($totalAno -eq 0) {
    '<div class="no-issues">Aucune anomalie detectee &mdash; Conformite RBAC validee !</div>'
} else {
@"
<div class="filter-box"><input type="text" id="filter-global" placeholder="Filtrer par nom, scope, role, souscription..." oninput="filterTable('tbl-global','filter-global')"></div>
<table id="tbl-global">
  <thead><tr><th>Type</th><th>Severite</th><th>Scope</th><th>Etendue initiale</th><th>Principal</th><th>Souscription</th><th>Role attribue</th><th>Role attendu</th><th>Description</th></tr></thead>
  <tbody>$globalRows</tbody>
</table>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Audit RBAC Azure - $REPORT_DATE</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;padding:20px}
.container{max-width:1800px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.4);overflow:hidden}
.header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:30px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
.header h1{font-size:2em;margin-bottom:6px}
.header-sub{opacity:.85;font-size:.95em}
.header-meta{text-align:right;font-size:.85em;opacity:.85;line-height:2}
.stats-global{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;padding:22px 30px;background:#f0f2f5}
.stat-card{background:#fff;border-radius:10px;padding:16px 18px;box-shadow:0 2px 10px rgba(0,0,0,.07);border-top:4px solid #667eea;transition:transform .2s}
.stat-card:hover{transform:translateY(-3px)}
.stat-card.red{border-top-color:#e74c3c}.stat-card.orange{border-top-color:#f39c12}.stat-card.blue{border-top-color:#2980b9}
.stat-card.purple{border-top-color:#8e44ad}.stat-card.green{border-top-color:#27ae60}.stat-card.gray{border-top-color:#95a5a6}
.stat-card h3{font-size:.72em;color:#6c757d;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.stat-card .num{font-size:2.2em;font-weight:700;color:#2c3e50}
.stat-card.red .num{color:#e74c3c}.stat-card.orange .num{color:#f39c12}.stat-card.blue .num{color:#2980b9}
.tabs{display:flex;background:#f8f9fa;border-bottom:2px solid #dee2e6;overflow-x:auto;padding:0 10px}
.tab{padding:13px 18px;cursor:pointer;border:none;background:none;font-size:.88em;font-weight:600;color:#6c757d;border-bottom:3px solid transparent;white-space:nowrap;transition:all .2s;display:flex;align-items:center;gap:6px}
.tab:hover{background:#e9ecef;color:#667eea}.tab.active{color:#667eea;border-bottom:3px solid #667eea;background:#fff}
.tab-badge{background:#e74c3c;color:#fff;border-radius:10px;padding:2px 7px;font-size:.73em;font-weight:700}
.tab-content{display:none;animation:fadeIn .25s}.tab-content.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.stats-mini{display:flex;gap:10px;padding:18px 30px;background:#f8f9fa;flex-wrap:wrap}
.stat-mini{background:#fff;border-radius:8px;padding:12px 18px;box-shadow:0 1px 6px rgba(0,0,0,.07);min-width:120px}
.stat-mini.s-orange{border-left:4px solid #f39c12}.stat-mini.s-red{border-left:4px solid #e74c3c}
.stat-mini.s-amber{border-left:4px solid #e67e22}.stat-mini.s-blue{border-left:4px solid #2980b9}.stat-mini.s-teal{border-left:4px solid #1abc9c}
.stat-mini-label{font-size:.72em;color:#6c757d;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.stat-mini-num{font-size:1.8em;font-weight:700;color:#2c3e50}
.content{padding:24px 30px}.section{margin-bottom:30px}
.section-title{font-size:1.1em;font-weight:700;color:#2c3e50;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid #667eea}
table{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 2px 10px rgba(0,0,0,.07);border-radius:10px;overflow:hidden;font-size:.86em}
thead{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}
th{padding:12px 11px;text-align:left;font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:.5px}
td{padding:10px 11px;border-bottom:1px solid #f0f2f5;vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#f8f9ff}
.scope-cell{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.82em;color:#555;cursor:pointer}
.desc-cell{max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.82em;color:#555;cursor:pointer}
.scope-cell.expanded,.desc-cell.expanded{white-space:normal;max-width:none}
.signin{color:#888;font-size:.85em}
.badge{display:inline-block;padding:3px 9px;border-radius:11px;font-size:.77em;font-weight:600;white-space:nowrap}
.badge-danger{background:#fde8e8;color:#c0392b}.badge-warning{background:#fef5e7;color:#d68910}
.badge-info{background:#d6eaf8;color:#1a5276}.badge-purple{background:#f0e6f6;color:#6c3483}
.badge-teal{background:#d1f2eb;color:#0e6655}.badge-gray{background:#f2f3f4;color:#566573}
.badge-role{background:#eaf4fb;color:#154360;font-family:monospace;font-size:.8em}
.badge-scope-type{background:#667eea;color:#fff;padding:4px 12px;border-radius:14px;font-size:.85em}
.filter-box{margin-bottom:14px}
.filter-box input{width:100%;padding:9px 13px;border:1.5px solid #dee2e6;border-radius:7px;font-size:.93em;transition:border .2s}
.filter-box input:focus{outline:none;border-color:#667eea}
.scope-header{margin-bottom:18px;padding:14px;background:#f8f9ff;border-radius:8px;border-left:4px solid #667eea}
.scope-title{font-size:1.2em;color:#2c3e50;margin:6px 0 3px}
.scope-path{font-family:monospace;font-size:.78em;color:#666;word-break:break-all}
.back-btn{display:inline-flex;align-items:center;gap:5px;padding:7px 16px;background:#667eea;color:#fff;border:none;border-radius:7px;cursor:pointer;font-size:.88em;margin-bottom:16px;transition:background .2s}
.back-btn:hover{background:#5a6fd6}
.progress-bar{display:inline-block;width:110px;height:9px;background:#f0f2f5;border-radius:5px;overflow:hidden;vertical-align:middle;margin-right:5px}
.progress-fill{height:100%;background:linear-gradient(to right,#667eea,#764ba2);border-radius:5px}
.no-issues{text-align:center;padding:40px;color:#27ae60;font-size:1.1em;font-weight:600}
.scope-stats-table th,.scope-stats-table td{padding:9px 12px;border-bottom:1px solid #f0f2f5;font-size:.9em}
.scope-stats-table thead th{background:#f8f9fa;color:#495057;font-weight:700;text-transform:none;letter-spacing:0}
.footer{background:#f8f9fa;padding:18px;text-align:center;color:#6c757d;font-size:.84em;border-top:1px solid #dee2e6;line-height:1.8}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <div>
    <h1>Audit RBAC Azure</h1>
    <p class="header-sub">Root Management Group : <strong>$RootManagementGroupId</strong></p>
  </div>
  <div class="header-meta">
    <div>Genere le $REPORT_DATE</div>
    <div>Tenant : $tenantIdHtml</div>
    <div>$($globalStats.TotalSubscriptions) souscription(s)</div>
  </div>
</div>
<div class="stats-global">
  <div class="stat-card"><h3>Total Assignments</h3><div class="num">$($globalStats.TotalAssignments)</div></div>
  <div class="stat-card red"><h3>Anomalies Totales</h3><div class="num">$($globalStats.TotalAnomalies)</div></div>
  <div class="stat-card red"><h3>Utilisateurs Directs</h3><div class="num">$($globalStats.DirectUsers)</div></div>
  <div class="stat-card orange"><h3>Nomenclature KO</h3><div class="num">$($globalStats.MismatchedGroups)</div></div>
  <div class="stat-card blue"><h3>Groupes</h3><div class="num">$($globalStats.TotalGroups)</div></div>
  <div class="stat-card purple"><h3>Service Principals</h3><div class="num">$($globalStats.TotalSPs)</div></div>
  <div class="stat-card gray"><h3>Ignorees (null)</h3><div class="num">$($globalStats.TotalSkipped)</div></div>
  <div class="stat-card green"><h3>Etendues fautives</h3><div class="num">$scopeTabCount</div></div>
</div>
<div class="tabs">$($tabButtons.ToString())</div>
<div id="global" class="tab-content active">
  <div class="content">
    <div class="section">
      <div class="section-title">Repartition par type d'etendue initiale</div>
      <table class="scope-stats-table">
        <thead><tr><th>Type d'etendue</th><th>Anomalies</th><th>Pourcentage</th></tr></thead>
        <tbody>$($scopeTypeRows.ToString())</tbody>
      </table>
    </div>
    <div class="section">
      <div class="section-title">Toutes les anomalies ($($globalStats.TotalAnomalies))</div>
      $globalTableBlock
    </div>
  </div>
</div>
$($tabContents.ToString())
<div class="footer">
  <p>Audit RBAC Azure v3.0.0</p>
  <p>$($globalStats.TotalSubscriptions) souscriptions &bull; $($globalStats.TotalAssignments) assignments &bull; $($globalStats.TotalAnomalies) anomalies &bull; $scopeTabCount etendues fautives</p>
</div>
</div>
<script>
function showTab(id){
  document.querySelectorAll('.tab-content').forEach(function(c){c.classList.remove('active');});
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
  var el=document.getElementById(id); if(el){el.classList.add('active');}
  var btn=Array.from(document.querySelectorAll('.tab')).find(function(b){var oc=b.getAttribute('onclick');return oc&&oc.indexOf("'"+id+"'")!==-1;});
  if(btn){btn.classList.add('active');}
  window.scrollTo({top:0,behavior:'smooth'});
}
function filterTable(tid,fid){
  var inp=document.getElementById(fid); if(!inp)return;
  var f=inp.value.toUpperCase();
  var tbl=document.getElementById(tid); if(!tbl)return;
  Array.from(tbl.getElementsByTagName('tr')).slice(1).forEach(function(tr){
    tr.style.display=(tr.textContent||tr.innerText).toUpperCase().indexOf(f)>-1?'':'none';
  });
}
document.addEventListener('click',function(e){
  if(e.target.classList.contains('scope-cell')||e.target.classList.contains('desc-cell')){
    e.target.classList.toggle('expanded');
  }
});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $HTML_PATH -Encoding UTF8 -Force
Write-Log "HTML : $HTML_PATH" "SUCCESS"

#endregion

#region ── OUVERTURE + RESUME ─────────────────────────────────────────────────

try {
    if ($IsLinux)       { $o=Get-Command xdg-open -EA SilentlyContinue; if($o){& xdg-open $HTML_PATH} }
    elseif ($IsMacOS)   { & open $HTML_PATH }
    else                { Start-Process $HTML_PATH }
} catch { Write-Log "Ouvrez manuellement : $HTML_PATH" "WARN" }

Write-Log "=================================================" "SUCCESS"
Write-Log " AUDIT TERMINE" "SUCCESS"
Write-Log "=================================================" "SUCCESS"
Write-Log " HTML : $HTML_PATH" "INFO"
Write-Log " CSV  : $CSV_PATH" "INFO"
Write-Log " JSON : $JSON_PATH" "INFO"
Write-Log "=================================================" "INFO"
Write-Log " Souscriptions      : $($globalStats.TotalSubscriptions)" "INFO"
Write-Log " Total assignments  : $($globalStats.TotalAssignments)" "INFO"
Write-Log " Anomalies totales  : $($globalStats.TotalAnomalies)" $(if($globalStats.TotalAnomalies -gt 0){"WARN"}else{"SUCCESS"})
Write-Log "   Utilisateurs directs : $($globalStats.DirectUsers)" "INFO"
Write-Log "   Nomenclature KO      : $($globalStats.MismatchedGroups)" "INFO"
Write-Log " Ignorees (null)    : $($globalStats.TotalSkipped)" "INFO"
Write-Log " Etendues fautives  : $scopeTabCount" "INFO"
Write-Log "=================================================" "INFO"

#endregion
