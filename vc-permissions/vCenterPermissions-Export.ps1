Import-Module VMware.VimAutomation.Core

# === CONFIGURATION ===

$vCenters = @("vc01.vmi","vc02.vmi", "vc03.vmi")

$basePath = "c:\vCenterPermissions"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $basePath "VIPermissions_Log_$timestamp.log"
$cred = Get-Credential -Message "Enter vCenter credentials"

# === LOGGING FUNCTION ===
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

# === EXPORT FUNCTION ===
function Export-VIPermissions {
    param (
        [string]$vcenter,
        [PSCredential]$cred
    )
    try {
        Write-Log "Connecting to $vcenter for export..."
        Connect-VIServer -Server $vcenter -Credential $cred -WarningAction SilentlyContinue -ErrorAction Stop

        $permissions = Get-VIPermission -ErrorAction Stop
        $exportPath = Join-Path $basePath "VIPermissions_${vcenter}_$timestamp.csv"
        $permissions | Export-Csv -Path $exportPath -NoTypeInformation

        Write-Log "Exported permissions to $exportPath"
        Disconnect-VIServer -Server $vcenter -Confirm:$false
        Write-Log "Disconnected from $vcenter after export."
    } catch {
        Write-Log "ERROR: Failed to export from $vcenter - $_" "ERROR"
    }
}

# === MAIN EXECUTION ===

# EXPORT LOOP
foreach ($vcenter in $vCenters) {
    Export-VIPermissions -vcenter $vcenter -cred $cred
}
