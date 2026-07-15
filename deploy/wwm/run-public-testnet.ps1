param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$RuntimeRoot = 'C:\mindchain\wwm-testnet',
    [string]$NodeBinary = 'C:\mindchain\wwm-testnet\bin\noosd.exe',
    [string]$PythonBinary = 'python.exe',
    [string]$CloudflaredBinary = 'C:\mindchain\wwm-testnet\bin\cloudflared-2026.7.2.exe',
    [string]$StaticBundleRoot = 'D:\noosphere-artifacts\public-testnet-web-bundle',
    [string]$StaticBundleOrigin = 'https://wwm-artifacts.mindchain.network',
    [string]$ArtifactServiceBinary = 'D:\noosphere-targets\integration\release\noos-artifact-service.exe',
    [string]$ArtifactStoreRoot = 'D:\noosphere-artifacts\custodian-store',
    [string]$ArtifactStagingRoot = 'D:\noosphere-artifacts\custodian-store\staging',
    [string]$ArtifactConsensusRoot = 'C:\tmp\wwm-consensus-placeholder',
    [string]$WorkerdBinary = 'D:\noosphere-targets\web-capacity\debug\noos-workerd.exe',
    [string]$WorkerdConfig = 'C:\mindchain\wwm-testnet\secrets\workerd.toml',
    [string]$CoordinatorBinary = 'D:\noosphere-targets\web-capacity\debug\noos-web-capacityd.exe',
    [string]$CoordinatorConfig = 'C:\mindchain\wwm-testnet\web-capacity\coordinator.json',
    [string]$CoordinatorSeedFile = 'C:\mindchain\wwm-testnet\secrets\web-capacity-coordinator-seed.hex',
    [string]$TunnelConfig = 'C:\mindchain\wwm-testnet\cloudflared.yml',
    [switch]$SkipTunnel
)

$ErrorActionPreference = 'Stop'
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$TokenFile = Join-Path $RuntimeRoot 'secrets\rpc-token.txt'
$DataDir = Join-Path $RuntimeRoot 'node'
$LogDir = Join-Path $RuntimeRoot 'logs'
$SiteRoot = Join-Path $RepoRoot 'site'
$GatewayScript = Join-Path $RepoRoot 'tools\operations\wwm_public_gateway.py'
$StaticHostScript = Join-Path $RepoRoot 'tools\operations\wwm_static_bundle_server.py'

foreach ($directory in @($DataDir, $LogDir)) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
foreach ($file in @(
    $NodeBinary,
    $TokenFile,
    $GatewayScript,
    $StaticHostScript,
    $CoordinatorBinary,
    $ArtifactServiceBinary,
    $WorkerdBinary,
    $WorkerdConfig,
    $CoordinatorConfig,
    $CoordinatorSeedFile
)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required public-testnet file is missing: $file"
    }
}
if (-not (Test-Path -LiteralPath $SiteRoot -PathType Container)) {
    throw "Site root is missing: $SiteRoot"
}
if (-not (Test-Path -LiteralPath $StaticBundleRoot -PathType Container)) {
    throw "Static artifact bundle is missing: $StaticBundleRoot"
}
foreach ($directory in @($ArtifactStoreRoot, $ArtifactStagingRoot, $ArtifactConsensusRoot)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Artifact runtime directory is missing: $directory"
    }
}
if (-not $SkipTunnel) {
    foreach ($file in @($TunnelConfig, $CloudflaredBinary)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Cloudflare tunnel input is missing: $file"
        }
    }
}
$Token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($Token.Length -lt 32 -or $Token -match '\s') {
    throw 'RPC token file must contain one non-whitespace token of at least 32 characters.'
}
Remove-Variable Token
$CoordinatorSeed = (Get-Content -LiteralPath $CoordinatorSeedFile -Raw).Trim()
if ($CoordinatorSeed -notmatch '^[0-9a-f]{64}$') {
    throw 'Web-capacity coordinator seed must be canonical lowercase hex32.'
}

$GovernanceAccount = '17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce'
$Specs = @(
    [pscustomobject]@{
        Name = 'node'
        Exe = $NodeBinary
        Args = @(
            '--validator',
            '--devnet-witness-fixture',
            '--devnet-bonsai-fixture',
            '--rpc', '127.0.0.1:29652',
            '--rpc-token-file', $TokenFile,
            '--produce-interval-ms', '1000',
            '--devnet-governance-account', $GovernanceAccount,
            '--p2p-listen', '/ip4/0.0.0.0/udp/29650/quic-v1',
            '--data-dir', $DataDir
        )
    },
    [pscustomobject]@{
        Name = 'artifact-store'
        Exe = $ArtifactServiceBinary
        Args = @(
            'serve',
            '--listen', '127.0.0.1:29682',
            '--store-root', $ArtifactStoreRoot,
            '--staging-root', $ArtifactStagingRoot,
            '--consensus-root', $ArtifactConsensusRoot,
            '--quota-bytes', '8589934592',
            '--max-concurrency', '4',
            '--queue-capacity', '16',
            '--per-client-rps', '128',
            '--max-range-bytes', '1047552',
            '--egress-bytes-per-second', '67108864',
            '--metrics-log-seconds', '30'
        )
    },
    [pscustomobject]@{
        Name = 'workerd'
        Exe = $WorkerdBinary
        Args = @('serve', '--config', $WorkerdConfig)
    },
    [pscustomobject]@{
        Name = 'static-host'
        Exe = $PythonBinary
        Args = @(
            $StaticHostScript,
            '--listen', '127.0.0.1:29681',
            '--bundle-root', $StaticBundleRoot,
            '--origin', $StaticBundleOrigin
        )
    },
    [pscustomobject]@{
        Name = 'web-capacity'
        Exe = $CoordinatorBinary
        Args = @('--config', $CoordinatorConfig)
        Environment = @{
            NOOS_WWM_WEB_CAPACITY_SEED = $CoordinatorSeed
        }
    },
    [pscustomobject]@{
        Name = 'gateway'
        Exe = $PythonBinary
        Args = @(
            $GatewayScript,
            '--listen', '127.0.0.1:29680',
            '--node-rpc', 'http://127.0.0.1:29652',
            '--node-token-file', $TokenFile,
            '--site-root', $SiteRoot,
            '--allow-origin', 'https://mindchain.network',
            '--allow-origin', 'https://wwm.mindchain.network'
        )
    }
)
Remove-Variable CoordinatorSeed
if (-not $SkipTunnel) {
    $Specs += [pscustomobject]@{
        Name = 'cloudflared'
        Exe = $CloudflaredBinary
        Args = @('--config', $TunnelConfig, 'tunnel', 'run', 'mindchain-wwm-testnet')
    }
}

$Children = @{}
$Backoff = @{}
foreach ($spec in $Specs) { $Backoff[$spec.Name] = 1 }

function Start-ManagedProcess([pscustomobject]$Spec) {
    $stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $stdout = Join-Path $LogDir "$($Spec.Name)-$stamp.log"
    $stderr = Join-Path $LogDir "$($Spec.Name)-$stamp.err.log"
    $environmentBackup = @{}
    try {
        if ($null -ne $Spec.PSObject.Properties['Environment']) {
            foreach ($name in $Spec.Environment.Keys) {
                $environmentBackup[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
                [Environment]::SetEnvironmentVariable(
                    $name,
                    [string]$Spec.Environment[$name],
                    'Process'
                )
            }
        }
        $process = Start-Process `
            -FilePath $Spec.Exe `
            -ArgumentList $Spec.Args `
            -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -WindowStyle Hidden `
            -PassThru
    } finally {
        foreach ($name in $environmentBackup.Keys) {
            [Environment]::SetEnvironmentVariable($name, $environmentBackup[$name], 'Process')
        }
    }
    $Children[$Spec.Name] = [pscustomobject]@{
        Process = $process
        StartedAt = [DateTimeOffset]::UtcNow
        Stdout = $stdout
        Stderr = $stderr
    }
    Write-Output "started $($Spec.Name) pid=$($process.Id) stdout=$stdout stderr=$stderr"
}

try {
    foreach ($spec in $Specs) { Start-ManagedProcess $spec }
    while ($true) {
        Start-Sleep -Seconds 2
        foreach ($spec in $Specs) {
            $managed = $Children[$spec.Name]
            if (-not $managed.Process.HasExited) {
                if (([DateTimeOffset]::UtcNow - $managed.StartedAt).TotalMinutes -ge 5) {
                    $Backoff[$spec.Name] = 1
                }
                continue
            }
            $exitCode = $managed.Process.ExitCode
            $delay = [int]$Backoff[$spec.Name]
            Write-Error "$($spec.Name) exited code=$exitCode; restarting after ${delay}s" -ErrorAction Continue
            Start-Sleep -Seconds $delay
            $Backoff[$spec.Name] = [Math]::Min(60, $delay * 2)
            Start-ManagedProcess $spec
        }
    }
}
finally {
    foreach ($managed in $Children.Values) {
        if (-not $managed.Process.HasExited) {
            Stop-Process -Id $managed.Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
