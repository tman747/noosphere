param(
    [string]$NetworkRoot = "C:\tmp\mindchain-lan-proof",
    [string]$ExpectedHost = "192.168.1.158",
    [ValidateSet("PrivateLan", "Tailscale")]
    [string]$NetworkMode = "PrivateLan",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Manifest = Join-Path $NetworkRoot "lan-manifest.json"
$OperatorSecret = Join-Path $NetworkRoot "operator-secret.json"
$ValidatorData = Join-Path $NetworkRoot "validator"
$Profile = Join-Path $NetworkRoot "wallet-profile-live.json"

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
    (Join-Path $Repo "target\release\noos-indexer.exe"),
    (Join-Path $Repo "target\debug\noos-indexer.exe")
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
        "-NetworkRoot", ('"' + $NetworkRoot + '"'),
        "-ExpectedHost", ('"' + $ExpectedHost + '"'),
        "-NetworkMode", $NetworkMode
    )
    Start-Process powershell.exe -Verb RunAs -ArgumentList $Arguments
    Write-Host "Approve the Windows administrator prompt to open the MindChain LAN ports." -ForegroundColor Yellow
    exit 0
}

$RulePrefix = if ($NetworkMode -eq "Tailscale") { "MindChain-Tailscale" } else { "MindChain-LAN" }
$RemoteAddress = if ($NetworkMode -eq "Tailscale") { "100.64.0.0/10" } else { "LocalSubnet" }
$FirewallRules = @(
    @{ Name = "$RulePrefix-P2P-UDP-21701"; Protocol = "UDP"; Port = 21701 },
    @{ Name = "$RulePrefix-API-TCP-21080"; Protocol = "TCP"; Port = 21080 },
    @{ Name = "$RulePrefix-Compute-TCP-18110"; Protocol = "TCP"; Port = 18110 },
    @{ Name = "$RulePrefix-Dashboard-TCP-18120"; Protocol = "TCP"; Port = 18120 },
    @{ Name = "$RulePrefix-Explorer-TCP-18130"; Protocol = "TCP"; Port = 18130 }
)
foreach ($rule in $FirewallRules) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
            -Protocol $rule.Protocol -LocalPort $rule.Port -Profile Private `
            -RemoteAddress $RemoteAddress | Out-Null
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
if ($Status -and [uint64]$Status.unsafe_head.height -ge 512 -and [uint64]$Status.finalized.epoch -eq 0) {
    Write-Warning "Finality is stalled at genesis; restarting the engineering host with standalone fixture finality."
    $NodeListener = Get-NetTCPConnection -LocalPort 21632 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($NodeListener) {
        Stop-Process -Id $NodeListener.OwningProcess -Force
        Start-Sleep -Seconds 1
    }
    $Status = $null
}
if (-not $Status) {
    $ValidatorArgs = @(
        (Join-Path $Repo "tools\lan_testnet.py"), "run-validator",
        "--manifest", $Manifest,
        "--operator-secret", $OperatorSecret,
        "--data-dir", $ValidatorData,
        "--standalone-finality"
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

$IndexerData = Join-Path $NetworkRoot "indexer"
$ApiReady = $false
$ApiRunning = $false
$ApiListener = Get-NetTCPConnection -LocalPort 21080 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($ApiListener) {
    try {
        $ApiStatus = Invoke-RestMethod -Uri "http://127.0.0.1:21080/api/status" -TimeoutSec 2
        if ($ApiStatus.PSObject.Properties.Name -contains "readiness") {
            $ApiRunning = $true
            $ApiReady = ($ApiStatus.ready -eq $true)
        }
    } catch {
        $ApiRunning = $false
    }
    if (-not $ApiRunning) {
        Stop-Process -Id $ApiListener.OwningProcess -Force
        Start-Sleep -Seconds 1
    }
}
if (-not $ApiRunning) {
    $IndexerArgs = @(
        (Join-Path $Repo "tools\lan_testnet.py"), "run-indexer",
        "--manifest", $Manifest,
        "--operator-secret", $OperatorSecret,
        "--public-host", $ExpectedHost,
        "--data-dir", $IndexerData,
        "--profile-out", $Profile
    )
    Start-Process python -WorkingDirectory $Repo -ArgumentList $IndexerArgs -WindowStyle Minimized
}
$MarketSeed = "C:\tmp\mindchain-owner.seed"
$MarketToken = "C:\tmp\mindchain-admin.token"
$MarketDatabase = "C:\tmp\mindchain-compute-live.sqlite3"
$MarketReady = $false
$MarketListener = Get-NetTCPConnection -LocalPort 18110 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($MarketListener) {
    try {
        $MarketHealth = Invoke-RestMethod -Uri "http://127.0.0.1:18110/api/health" -TimeoutSec 2
        $MarketReady = ($MarketHealth.version -eq "0.2" -and $MarketHealth.operator_head -eq $true)
    } catch {
        $MarketReady = $false
    }
    if (-not $MarketReady) {
        Stop-Process -Id $MarketListener.OwningProcess -Force
        Start-Sleep -Seconds 1
    }
}
if (-not $MarketReady -and (Test-Path -LiteralPath $MarketSeed) -and (Test-Path -LiteralPath $MarketToken)) {
    $Deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $ApiStatus = Invoke-RestMethod -Uri "http://127.0.0.1:21080/api/status" -TimeoutSec 2
            $ApiReady = ($ApiStatus.ready -eq $true)
        } catch {
            $ApiReady = $false
        }
    } until (($ApiReady -and (Test-Path -LiteralPath $Profile)) -or (Get-Date) -ge $Deadline)
    if ($ApiReady -and (Test-Path -LiteralPath $Profile)) {
        $MarketArgs = @(
            (Join-Path $Repo "tools\compute_market.py"),
            "--profile", $Profile,
            "--seed-file", $MarketSeed,
            "--listen", "0.0.0.0:18110",
            "--database", $MarketDatabase,
            "--admin-token-file", $MarketToken,
            "--operator-node", "127.0.0.1:21632",
            "--operator-token-file", $OperatorSecret
        )
        Start-Process python -WorkingDirectory $Repo -ArgumentList $MarketArgs -WindowStyle Minimized
        $MarketReady = $true
    }
}
if (-not $MarketReady) {
    Write-Warning "The validator is online, but the optional compute market did not start."
}

$DashboardReady = $false
try {
    $DashboardHealth = Invoke-RestMethod -Uri "http://127.0.0.1:18120/api/health" -TimeoutSec 2
    $DashboardReady = ($DashboardHealth.schema -eq "noos/network-dashboard-health/v1")
} catch {
    $DashboardReady = $false
}
if (-not $DashboardReady) {
    $DashboardArgs = @(
        (Join-Path $Repo "tools\network_dashboard.py"),
        "--operator-node", "http://127.0.0.1:21632",
        "--operator-secret", $OperatorSecret,
        "--indexer", "http://127.0.0.1:21080",
        "--compute", "http://127.0.0.1:18110",
        "--database", (Join-Path $NetworkRoot "network-dashboard.sqlite3"),
        "--listen", "0.0.0.0:18120"
    )
    Start-Process python -WorkingDirectory $Repo -ArgumentList $DashboardArgs -WindowStyle Minimized
    $DashboardDeadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 300
        try {
            $DashboardHealth = Invoke-RestMethod -Uri "http://127.0.0.1:18120/api/health" -TimeoutSec 2
            $DashboardReady = ($DashboardHealth.schema -eq "noos/network-dashboard-health/v1")
        } catch {
            $DashboardReady = $false
        }
    } until ($DashboardReady -or (Get-Date) -ge $DashboardDeadline)
}
if (-not $DashboardReady) {
    Write-Warning "The validator is online, but the network dashboard did not start."
}

$ExplorerReady = $false
try {
    $ExplorerHealth = Invoke-RestMethod -Uri "http://127.0.0.1:18130/api/health" -TimeoutSec 2
    $ExplorerReady = ($ExplorerHealth.schema -eq "noos/mindscan-health/v1")
} catch {
    $ExplorerReady = $false
}
if (-not $ExplorerReady) {
    $ExplorerArgs = @(
        (Join-Path $Repo "tools\mindscan.py"),
        "--indexer", "http://127.0.0.1:21080",
        "--listen", "0.0.0.0:18130"
    )
    Start-Process python -WorkingDirectory $Repo -ArgumentList $ExplorerArgs -WindowStyle Minimized
    $ExplorerDeadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 300
        try {
            $ExplorerHealth = Invoke-RestMethod -Uri "http://127.0.0.1:18130/api/health" -TimeoutSec 2
            $ExplorerReady = ($ExplorerHealth.schema -eq "noos/mindscan-health/v1")
        } catch {
            $ExplorerReady = $false
        }
    } until ($ExplorerReady -or (Get-Date) -ge $ExplorerDeadline)
}
if (-not $ExplorerReady) {
    Write-Warning "The validator is online, but MindScan did not start."
}

$ReadinessProbe = Join-Path $Repo "tools\network_readiness.py"
$ReadinessJson = & python $ReadinessProbe `
    --operator-secret $OperatorSecret `
    --indexer "http://127.0.0.1:21080" `
    --mindscan "http://127.0.0.1:18130" `
    --compute "http://127.0.0.1:18110" `
    --dashboard "http://127.0.0.1:18120" `
    --advance-seconds 2
if ($LASTEXITCODE -ne 0) {
    throw "MindChain service stack failed the readiness gate: $ReadinessJson"
}
Write-Host $ReadinessJson

Write-Host "MindChain invitation host is online." -ForegroundColor Green
Write-Host "Validator: $ExpectedHost UDP 21701"
Write-Host "Public API: http://${ExpectedHost}:21080"
Write-Host "Network dashboards: http://${ExpectedHost}:18120"
Write-Host "MindScan explorer: http://${ExpectedHost}:18130"
Write-Host "Keep this PC awake and connected while invited nodes are running."
