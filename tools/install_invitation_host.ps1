param(
    [string]$NetworkRoot = "C:\tmp\mindchain-lan-proof",
    [string]$InstallRoot = "$env:ProgramData\MindChain\Host",
    [string]$DataRoot = "$env:ProgramData\MindChain\Data",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$TaskName = "MindChain Invitation Host"
$IsAdministrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdministrator -and -not $CheckOnly) {
    $Arguments = @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'),
        "-NetworkRoot", ('"' + $NetworkRoot + '"'),
        "-InstallRoot", ('"' + $InstallRoot + '"'),
        "-DataRoot", ('"' + $DataRoot + '"')
    )
    if ($CheckOnly) { $Arguments += "-CheckOnly" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $Arguments
    exit 0
}

foreach ($required in @(
    (Join-Path $NetworkRoot "lan-manifest.json"),
    (Join-Path $NetworkRoot "operator-secret.json"),
    (Join-Path $Repo "tools\start_invitation_host.ps1"),
    (Join-Path $Repo "tools\run_installed_host.ps1")
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required host artifact is missing: $required"
    }
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3 is required by the compute coordinator and dashboard."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "Cargo is required once to locate the built release binaries."
}
$Metadata = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
$Target = [string]$Metadata.target_directory
$NodeBinary = Join-Path $Target "debug\noosd.exe"
$IndexerBinary = Join-Path $Target "release\noos-indexer.exe"
$CliBinary = Join-Path $Target "release\noos-cli.exe"
foreach ($binary in @($NodeBinary, $IndexerBinary, $CliBinary)) {
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "Host binary is missing: $binary. Build noos-node debug, noos-indexer release, and noos-cli release first."
    }
}
if ($CheckOnly) {
    Write-Host "MindChain host installer prerequisites are present." -ForegroundColor Green
    Write-Host "Node binary: $NodeBinary"
    Write-Host "Indexer binary: $IndexerBinary"
    Write-Host "CLI binary: $CliBinary"
    Write-Host "Network root: $NetworkRoot"
    exit 0
}

# Stop a prior managed task and only listeners attributable to this checkout or
# an earlier installed runtime. Never terminate an unrelated process by port.
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}
foreach ($port in @(21632, 21080, 18110, 18120, 18130)) {
    $Listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $Listener) { continue }
    $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$($Listener.OwningProcess)" -ErrorAction SilentlyContinue
    if (-not $Process) { continue }
    $Executable = [string]$Process.ExecutablePath
    $CommandLine = [string]$Process.CommandLine
    $OwnedExecutable = (
        $Executable.Equals($NodeBinary, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Executable.Equals($IndexerBinary, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Executable.StartsWith($InstallRoot, [System.StringComparison]::OrdinalIgnoreCase)
    )
    $OwnedPython = (
        $Process.Name -eq "python.exe" -and
        ($CommandLine.Contains($Repo) -or $CommandLine.Contains($NetworkRoot) -or $CommandLine.Contains($InstallRoot))
    )
    if ($OwnedExecutable -or $OwnedPython) {
        Stop-Process -Id $Listener.OwningProcess -Force
    } else {
        throw "Port $port is occupied by unmanaged process $($Listener.OwningProcess); refusing to terminate it."
    }
}
Start-Sleep -Seconds 1

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallRoot "tools") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallRoot "apps") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallRoot "target\release") -Force | Out-Null
New-Item -ItemType Directory -Path $DataRoot -Force | Out-Null

$ToolFiles = @(
    "start_invitation_host.ps1",
    "run_installed_host.ps1",
    "lan_testnet.py",
    "compute_market.py",
    "compute_worker.py",
    "wallet_transfer.py",
    "network_dashboard.py",
    "fleet_telemetry.py",
    "mindscan.py",
    "start_tailscale_host.ps1",
    "invitation_leases.py",
    "build_join_bundle.py",
    "operator_onboard.ps1",
    "operator_onboard.command",
    "node_status_dashboard.py"
)
foreach ($name in $ToolFiles) {
    Copy-Item -LiteralPath (Join-Path $Repo "tools\$name") -Destination (Join-Path $InstallRoot "tools\$name") -Force
}
Copy-Item -LiteralPath (Join-Path $Repo "apps\compute-market") -Destination (Join-Path $InstallRoot "apps") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $Repo "apps\network-dashboard") -Destination (Join-Path $InstallRoot "apps") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $Repo "apps\mindscan") -Destination (Join-Path $InstallRoot "apps") -Recurse -Force
Copy-Item -LiteralPath $NodeBinary -Destination (Join-Path $InstallRoot "target\release\noosd.exe") -Force
Copy-Item -LiteralPath $IndexerBinary -Destination (Join-Path $InstallRoot "target\release\noos-indexer.exe") -Force
Copy-Item -LiteralPath $CliBinary -Destination (Join-Path $InstallRoot "target\release\noos-cli.exe") -Force
Copy-Item -Path (Join-Path $NetworkRoot "*") -Destination $DataRoot -Recurse -Force
$InstalledManifest = Join-Path $DataRoot "lan-manifest.json"
$ManifestValue = Get-Content -LiteralPath $InstalledManifest -Raw | ConvertFrom-Json
$ParamsSource = [string]$ManifestValue.params
if (-not [System.IO.Path]::IsPathRooted($ParamsSource)) {
    $ParamsSource = Join-Path $Repo $ParamsSource
}
if (-not (Test-Path -LiteralPath $ParamsSource)) {
    throw "Genesis parameter file referenced by the manifest is missing: $ParamsSource"
}
$InstalledParams = Join-Path $DataRoot "devnet-parameters.toml"
Copy-Item -LiteralPath $ParamsSource -Destination $InstalledParams -Force
$ManifestValue.params = $InstalledParams
$ManifestTemporary = $InstalledManifest + ".tmp"
$ManifestJson = $ManifestValue | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($ManifestTemporary, $ManifestJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $ManifestTemporary -Destination $InstalledManifest -Force

$SecretPath = Join-Path $DataRoot "operator-secret.json"
& icacls.exe $SecretPath /inheritance:r /grant:r "SYSTEM:(F)" "Administrators:(F)" | Out-Null

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (
    "-NoProfile -ExecutionPolicy Bypass -File `"" +
    (Join-Path $InstallRoot "tools\run_installed_host.ps1") + "`" -InstallRoot `"$InstallRoot`" -DataRoot `"$DataRoot`""
)
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet `
    -RestartCount 100 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "MindChain producer, indexer, compute coordinator, network dashboard, and explorer" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "MindChain host installed." -ForegroundColor Green
Write-Host "Task: $TaskName"
Write-Host "Runtime: $InstallRoot"
Write-Host "Protected data: $DataRoot"
Write-Host "Dashboard: http://192.168.1.158:18120"
Write-Host "Explorer: http://192.168.1.158:18130"
