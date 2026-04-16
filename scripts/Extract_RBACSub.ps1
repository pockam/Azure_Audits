#Connectez-vous à votre compte Azure
Connect-AzAccount -UseDeviceAuthentication

# Récupérez toutes les souscriptions
$subscriptions = Get-AzSubscription

# Filtrez les souscriptions contenant "Storage" ou "AU Microsoft Azure Enterprise"
$filteredSubscriptions = $subscriptions | Where-Object { 
    $_.Name -like "*Storage*" -or $_.Name -eq "AU Microsoft Azure Enterprise" 
}

# Définir le répertoire de sortie et créer s'il n'existe pas
$outputDir = "/home/pockam/clouddrive/reports"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Répertoire créé : $outputDir"
}

# Nom du fichier CSV avec horodatage
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvFilePath = Join-Path -Path $outputDir -ChildPath "AzureRoleAssignments_$timestamp.csv"

# Initialisez une liste pour stocker les résultats
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Parcourez chaque souscription filtrée
foreach ($subscription in $filteredSubscriptions) {
    Write-Host "Traitement de la souscription : $($subscription.Name)" -ForegroundColor Cyan

    # Sélectionnez la souscription
    Select-AzSubscription -SubscriptionId $subscription.Id | Out-Null

    # Récupérez les rôles d'accès pour la souscription
    $roles = Get-AzRoleAssignment

    # Ajoutez les informations à la liste des résultats
    foreach ($role in $roles) {
        $results.Add([PSCustomObject]@{
            SubscriptionName = $subscription.Name
            RoleName         = $role.RoleDefinitionName
            PrincipalName    = $role.PrincipalName
            PrincipalType    = $role.PrincipalType
            Scope            = $role.Scope
        })
    }
}

# Exportez les résultats dans le fichier CSV
$results | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8

Write-Host "`n✅ Export terminé avec succès !" -ForegroundColor Green
Write-Host "📄 Fichier généré : $csvFilePath" -ForegroundColor Yellow
Write-Host "📊 Nombre total d'entrées : $($results.Count)" -ForegroundColor Yellow
