
**# Création d’un profil persistant pour stocker les scripts sur le CloudShell Azure**

Le fichier $PROFILE dans cloudshell te permet de définir :
	Alias personnalisés (Set-Alias)
	Fonctions réutilisables
	Commandes de démarrage
	Importation de module ou de script

Pour avoir un profil persistant après l’arrêt de la session il est impératif d’avoir un FileShare monté sur votre session utilisateur et si ce n’est pas le cas rendez-vous en haut de votre session cloudshell sur settingsreset user settings pour monter un fileshare sur votre session utilisateur.
Le fichier $PROFILE par défaut est logé dans le répertoire /home/utilisateur/.config/PowerShell/Microsoft.PowerShell_profile.ps1 il est en lecture seule donc impossible à modifier il faut en créer un nouveau.
Nous allons créer un dossier Clouddrive dans le lequel nous stockerons : le profil, les scripts et les rapports
New-Item -ItemType Directory -Path ~/clouddrive  -Force
Création de la structure du clouddrive
New-Item -ItemType Directory -Path ~/clouddrive/scripts -Force 
New-Item -ItemType Directory -Path ~/clouddrive/reports -Force 
New-Item -ItemType Directory -Path ~/clouddrive/config -Force 
Créer le fichier profil source dans clouddrive 
New-Item -ItemType File -Path ~/clouddrive/profile.ps1 -Force

**## Création du lien vers le $PROFILE(symlink) vers clouddrive**
Suppression du fichier existant
Remove-Item $PROFILE -Force
Création du symlink
New-Item -ItemType SymbolicLink ` -Path $PROFILE ` -Target   "$HOME/clouddrive/profile.ps1" ` -Force
Vous pouvez à present charger le $profile avec un comportement par défaut que vous souhaitez. Voici celui que j’ai utilisé par défaut :
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
export SCRIPTS = "$HOME/clouddrive/scripts"
export REPORTS = "$HOME/clouddrive/reports"
export CONFIG  = "$HOME/clouddrive/config"

Write-Host "  Scripts : $env:SCRIPTS" -ForegroundColor DarkGray
Write-Host "  Reports : $env:REPORTS" -ForegroundColor DarkGray
Write-Host ""


