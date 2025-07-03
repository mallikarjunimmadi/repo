Import-Module VMware.VimAutomation.Core
$vCenter = "vc01.vmi"  ######update vCenter here#####
$cred = Get-Credential -Message "Enter vCenter credentials"
Connect-VIServer -Server $vCenter -Credential $cred 
$importRows = Import-Csv "C:\vCenterPermissions\<fileNameGeneratedUsingExportScript>" -ErrorAction Stop ####update file name here####

####DO NOT EDIT BEYOND THIS LINE####
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
#$logFile = Join-Path $basePath "c:\vCenterPermissions\VIPermissions_Apply_Log_$timestamp.log"
$logFile ="c:\vCenterPermissions\VIPermissions_Apply_Log_$timestamp.log"
function Write-Log {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestampNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $formattedMessage = "[$timestampNow][$level] $message"
    Write-Host $formattedMessage
    Add-Content -Path $logFile -Value $formattedMessage
}
foreach ($row in $importRows) {

           <# Write-Host "Principal: " $($row.Principal)
            Write-Host "Entity   : "$($row.Entity)
            Write-Host "EntityID : "$($row.EntityId)
            Write-Host "Role     : "$($row.Role)
            Write-Host "Propogate: "$($row.Propagate)
            Write-Host "IsGroup  : "$($row.IsGroup)
            #>
            $entity = New-Object VMware.Vim.ManagedObjectReference
            
            $entity.Type = ($row.EntityId -split '-')[0]
            Write-Log "Entity Type: $($entity.Type)"
            
            #$entity.Value = (Get-Folder -Name $($row.EntityId)).Replace("$($entity.Type)-",'')
            $eId = ($row.EntityId).Replace("$($entity.Type)-",'')
            $entity.Value = $eId
            Write-Log "Entity Id Value: $($entity.Value)"
            
            $permission = New-Object VMware.Vim.Permission[] (1)
            $permission[0] = New-Object VMware.Vim.Permission
            $permission[0].Principal = $($row.Principal_v1)
            $permission[0].RoleId = (Get-VIRole -Name $row.Role).Id
            
            $propo = $row.Propagate -match "TRUE"
            if ($propo){
            $permission[0].Propagate = $true
            }
            else{
            $permission[0].Propagate = $false
            }
            $grp = $row.IsGroup -match "TRUE"
            if ($grp){
             $permission[0].Group = $true
            }
            else{
             $permission[0].Group = $false
            }         
           
            $_this = Get-View -Id 'AuthorizationManager-AuthorizationManager'
            try{
            $_this.SetEntityPermissions($entity, $permission)
            Write-Log "Permissions applied on $($entity.Value) for user $($row.Principal_v1)"
            }
            catch{
            Write-Log "Can't apply permissions on $($entity.Value) for user $($row.Principal_v1)"
            }
}

            
Disconnect-VIServer * -Confirm:$false
Write-Log "Disconnected from vCenter: $vCenter" -ForegroundColor Yellow
