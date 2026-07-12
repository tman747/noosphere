param(
    [string]$InstallRoot = "$env:ProgramData\MindChain\Host",
    [string]$DataRoot = "$env:ProgramData\MindChain\Data",
    [switch]$DeleteData
)

$ErrorActionPreference = "Stop"
$TaskName = "MindChain Invitation Host"
$IsAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdministrator) {
    $Arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'),
        "-InstallRoot", ('"' + $InstallRoot + '"'),
        "-DataRoot", ('"' + $DataRoot + '"')
    )
    if ($DeleteData) { $Arguments += "-DeleteData" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $Arguments
    exit 0
}

$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
foreach ($port in @(21632, 21080, 18110, 18120, 18130)) {
    $Listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Listener) {
        $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$($Listener.OwningProcess)" -ErrorAction SilentlyContinue
        if ($Process -and ([string]$Process.ExecutablePath).StartsWith($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $Listener.OwningProcess -Force
        } elseif ($Process -and $Process.Name -eq "python.exe" -and ([string]$Process.CommandLine).Contains($InstallRoot)) {
            Stop-Process -Id $Listener.OwningProcess -Force
        }
    }
}
foreach ($name in @(
    "MindChain-P2P-UDP-21701",
    "MindChain-API-TCP-21080",
    "MindChain-Compute-TCP-18110",
    "MindChain-Dashboard-TCP-18120",
    "MindChain-Explorer-TCP-18130",
    "MindChain-LAN-P2P-UDP-21701",
    "MindChain-LAN-API-TCP-21080",
    "MindChain-LAN-Compute-TCP-18110",
    "MindChain-LAN-Dashboard-TCP-18120",
    "MindChain-LAN-Explorer-TCP-18130",
    "MindChain-Tailscale-P2P-UDP-21701",
    "MindChain-Tailscale-API-TCP-21080",
    "MindChain-Tailscale-Compute-TCP-18110",
    "MindChain-Tailscale-Dashboard-TCP-18120",
    "MindChain-Tailscale-Explorer-TCP-18130"
)) {
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force
}
if ($DeleteData -and (Test-Path -LiteralPath $DataRoot)) {
    Remove-Item -LiteralPath $DataRoot -Recurse -Force
    Write-Host "MindChain host and protected data removed." -ForegroundColor Yellow
} else {
    Write-Host "MindChain host removed. Protected data was preserved at $DataRoot." -ForegroundColor Green
}
