param(
    [string]$NetworkRoot = "C:\tmp\mindchain-lan-proof",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Manifest = Join-Path $NetworkRoot "lan-manifest.json"
$OperatorSecret = Join-Path $NetworkRoot "operator-secret.json"
$ValidatorData = Join-Path $NetworkRoot "validator"
$Profile = Join-Path $NetworkRoot "wallet-profile-live.json"
$ExpectedHost = "192.168.1.158"

foreach ($path in @($Manifest, $OperatorSecret)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "MindChain host file is missing: $path"
    }
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is required on the host PC. Install Python 3 and run this command again."
}
$NodeBinary = @(
    (Join-Path $Repo "target\debug\noosd.exe"),
    (Join-Path $Repo "target\release\noosd.exe")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$IndexerBinary = @(
    (Join-Path $Repo "target\debug\noos-indexer.exe"),
    (Join-Path $Repo "target\release\noos-indexer.exe")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $NodeBinary -or -not $IndexerBinary) {
    throw "MindChain host binaries are missing. Build noosd and noos-indexer before starting the invitation host."
}

$LocalAddresses = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" } |
    Select-Object -ExpandProperty IPAddress
if ($ExpectedHost -notin $LocalAddresses) {
    throw "This invitation release expects host IP $ExpectedHost, but this PC currently has: $($LocalAddresses -join ', '). Reserve $ExpectedHost in the router or rebuild the invitations for the current address."
}
if ($CheckOnly) {
    Write-Host "MindChain invitation host prerequisites are present." -ForegroundColor Green
    Write-Host "Host address: $ExpectedHost"
    Write-Host "Node binary: $NodeBinary"
    Write-Host "Indexer binary: $IndexerBinary"
    exit 0
}

$IsAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdministrator) {
    $Arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'),
        "-NetworkRoot", ('"' + $NetworkRoot + '"')
    )
    Start-Process powershell.exe -Verb RunAs -ArgumentList $Arguments
    Write-Host "Approve the Windows administrator prompt to open the MindChain LAN ports." -ForegroundColor Yellow
    exit 0
}

$FirewallRules = @(
    @{ Name = "MindChain-P2P-UDP-21701"; Protocol = "UDP"; Port = 21701 },
    @{ Name = "MindChain-API-TCP-21080"; Protocol = "TCP"; Port = 21080 },
    @{ Name = "MindChain-Compute-TCP-18110"; Protocol = "TCP"; Port = 18110 }
)
foreach ($rule in $FirewallRules) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
            -Protocol $rule.Protocol -LocalPort $rule.Port -Profile Private | Out-Null
    }
}

$Secret = Get-Content -LiteralPath $OperatorSecret -Raw | ConvertFrom-Json
$Headers = @{ Authorization = "Bearer $($Secret.rpc_token)" }
$Status = $null
try {
    $Status = Invoke-RestMethod -Uri "http://127.0.0.1:21632/status" -Headers $Headers -TimeoutSec 2
} catch {
    $Status = $null
}
if (-not $Status) {
    $ValidatorArgs = @(
        (Join-Path $Repo "tools\lan_testnet.py"), "run-validator",
        "--manifest", $Manifest,
        "--operator-secret", $OperatorSecret,
        "--data-dir", $ValidatorData
    )
    Start-Process python -WorkingDirectory $Repo -ArgumentList $ValidatorArgs -WindowStyle Minimized
    $Deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $Status = Invoke-RestMethod -Uri "http://127.0.0.1:21632/status" -Headers $Headers -TimeoutSec 2
        } catch {
            $Status = $null
        }
    } until ($Status -or (Get-Date) -ge $Deadline)
    if (-not $Status) {
        throw "The MindChain validator did not start within 30 seconds."
    }
}

$ApiReady = $false
try {
    $ApiReady = $null -ne (Invoke-RestMethod -Uri "http://127.0.0.1:21080/api/status" -TimeoutSec 2)
} catch {
    $ApiReady = $false
}
if (-not $ApiReady) {
    $Session = Join-Path $NetworkRoot ("indexer-session-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    $IndexerArgs = @(
        (Join-Path $Repo "tools\lan_testnet.py"), "run-indexer",
        "--manifest", $Manifest,
        "--operator-secret", $OperatorSecret,
        "--public-host", $ExpectedHost,
        "--data-dir", $Session,
        "--profile-out", $Profile
    )
    Start-Process python -WorkingDirectory $Repo -ArgumentList $IndexerArgs -WindowStyle Minimized
}

Write-Host "MindChain invitation host is online." -ForegroundColor Green
Write-Host "Validator: $ExpectedHost UDP 21701"
Write-Host "Public API: http://${ExpectedHost}:21080"
Write-Host "Keep this PC awake and connected while invited nodes are running."
