param(
    [string]$InstallRoot = "$env:ProgramData\MindChain\Host",
    [string]$DataRoot = "$env:ProgramData\MindChain\Data"
)

$ErrorActionPreference = "Stop"
$LogRoot = Join-Path $DataRoot "logs"
New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
$Log = Join-Path $LogRoot ("host-" + (Get-Date -Format "yyyyMMdd") + ".log")
Start-Transcript -Path $Log -Append | Out-Null
$Launcher = Join-Path $InstallRoot "tools\start_invitation_host.ps1"
try {
    while ($true) {
        try {
            & $Launcher -NetworkRoot $DataRoot
        } catch {
            Write-Warning ("Host reconciliation failed: " + $_.Exception.Message)
        }
        # The launcher is idempotent: each pass checks the authenticated node,
        # public indexer, compute coordinator, and dashboard before starting a
        # missing component. Keeping this supervisor alive also gives Task
        # Scheduler a process to restart after an unexpected host-runner exit.
        Start-Sleep -Seconds 15
    }
} finally {
    Stop-Transcript | Out-Null
}
