# ─── CONTEXTE AU DÉMARRAGE ────────────────────────────────
$ctx = Get-AzContext
Write-Host ""
Write-Host "  Session active" -ForegroundColor Cyan
Write-Host "  Sub  : $($ctx.Subscription.Name)" -ForegroundColor Yellow
Write-Host "  User : $($ctx.Account.Id)" -ForegroundColor Gray
Write-Host ""

# ─── ALIAS ────────────────────────────────────────────────
Set-Alias ll Get-ChildItem
Set-Alias grep Select-String

# ─── FONCTIONS D'AUDIT ────────────────────────────────────
function Get-MyContext {
    Get-AzContext | Select-Object `
        @{N='Subscription';E={$_.Subscription.Name}},
        @{N='Tenant';E={$_.Tenant.Id}},
        @{N='User';E={$_.Account.Id}}
}

function Get-AuditRBAC {
    param([string]$SubscriptionId = (Get-AzContext).Subscription.Id)
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    Get-AzRoleAssignment | Select-Object `
        SignInName, DisplayName, RoleDefinitionName, Scope |
    Sort-Object Scope
}

function Get-UntaggedResources {
    Get-AzResource |
    Where-Object { -not $_.Tags -or $_.Tags.Count -eq 0 } |
    Select-Object Name, ResourceType, ResourceGroupName, Location
}

function Switch-Sub {
    param([string]$SubName)
    Set-AzContext -Subscription $SubName
    Write-Host "  Switched to : $SubName" -ForegroundColor Green
}

# ─── CHEMINS PERSISTANTS ──────────────────────────────────
$env:SCRIPTS = "$HOME/clouddrive/scripts"
$env:REPORTS = "$HOME/clouddrive/reports"
$env:CONFIG  = "$HOME/clouddrive/config"

Write-Host "  Scripts : $env:SCRIPTS" -ForegroundColor DarkGray
Write-Host "  Reports : $env:REPORTS" -ForegroundColor DarkGray
Write-Host ""

