param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$RuntimeRoot = 'C:\mindchain\wwm-testnet',
    [string]$NodeBinary = 'C:\mindchain\wwm-testnet\bin\noosd.exe',
    [string]$WalletCliBinary = 'C:\mindchain\wwm-testnet\bin\noos-cli.exe',
    [string]$WalletApiBase = 'https://wwm-seed-2.mindchain.network',
    [string]$WalletFaucetDb = 'C:\mindchain\wwm-testnet\wallet\faucet.sqlite3',
    [string]$Seed2RpcTokenFile = 'C:\mindchain\wwm-testnet\secrets\seed2-rpc-token.txt',
    [string]$SshBinary = 'C:\Windows\System32\OpenSSH\ssh.exe',
    [string]$Seed2SshTarget = 'azureuser@172.202.41.123',
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
    [string]$MonitorSigningKey = 'C:\mindchain\wwm-testnet\secrets\monitor-ed25519.seed',
    [string]$MonitorEvidenceDir = 'C:\mindchain\wwm-testnet\evidence',
    [string]$R2Report = 'C:\mindchain\wwm-testnet\web-capacity\r2-sync-20260715.json',
    [string]$NeuralPublisherHostedConfig = 'C:\mindchain\wwm-testnet\secrets\hosted-model-publisher.json',
    [string]$NeuralPublisherStateRoot = 'C:\mindchain\wwm-testnet\neural-publisher',
    [int]$NeuralPublisherMinimumSeconds = 21600,
    [string]$InferenceSecrets = 'C:\mindchain\wwm-testnet\secrets\public-inference.json',
    [string]$InferenceDatabase = 'C:\mindchain\wwm-testnet\inference\public-inference.sqlite3',
    [string]$InferenceWorkerOrigin = 'http://127.0.0.1:29807',
    [string]$InferenceTokenizer = 'D:\noosphere-artifacts\runtime\hip-run\llama-tokenize.exe',
    [string]$InferenceModel = 'D:\noosphere-artifacts\demo-disposable\model\Bonsai-27B-Q1_0.gguf',
    [string]$InferenceTokenizerSha256 = '2685f72d8b2c27c72c116d2c6af9bb180adb4bf2f4fc9adee052dbcfe7f266f4',
    [string]$SeedHostname = 'wwm-seed.mindchain.network',
    [string]$SeedIp = '20.15.164.29',
    [switch]$SkipTunnel
)

$ErrorActionPreference = 'Stop'
$CreatedSupervisorMutex = $false
$SupervisorMutex = [Threading.Mutex]::new(
    $true,
    'Local\MindChainWWMTestnetSupervisor',
    [ref]$CreatedSupervisorMutex
)
if (-not $CreatedSupervisorMutex) {
    $SupervisorMutex.Dispose()
    throw 'Another MindChain WWM public-testnet supervisor is already running.'
}
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$TokenFile = Join-Path $RuntimeRoot 'secrets\rpc-token.txt'
$Seed2RpcTokenFile = [IO.Path]::GetFullPath($Seed2RpcTokenFile)
$DataDir = Join-Path $RuntimeRoot 'node'
$LogDir = Join-Path $RuntimeRoot 'logs'
$SiteRoot = Join-Path $RepoRoot 'site'
$GatewayScript = Join-Path $RepoRoot 'tools\operations\wwm_public_gateway.py'
$StaticHostScript = Join-Path $RepoRoot 'tools\operations\wwm_static_bundle_server.py'
$MonitorScript = Join-Path $RepoRoot 'tools\operations\wwm_public_testnet_monitor.py'
$DeploymentManifest = Join-Path $RepoRoot 'deploy\wwm\public-testnet.json'
$NeuralPublisherScript = Join-Path $RepoRoot 'tools\operations\wwm_neural_publisher.py'

foreach ($directory in @($DataDir, $LogDir, $MonitorEvidenceDir, $NeuralPublisherStateRoot, (Join-Path $NeuralPublisherStateRoot 'evidence'), (Split-Path -Parent $InferenceDatabase))) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
foreach ($file in @(
    $NodeBinary,
    $TokenFile,
    $Seed2RpcTokenFile,
    $SshBinary,
    $GatewayScript,
    $StaticHostScript,
    $CoordinatorBinary,
    $ArtifactServiceBinary,
    $WorkerdBinary,
    $WorkerdConfig,
    $CoordinatorConfig,
    $CoordinatorSeedFile,
    $MonitorScript,
    $DeploymentManifest,
    $MonitorSigningKey,
    $R2Report,
    $NeuralPublisherScript,
    $NeuralPublisherHostedConfig,
    $InferenceSecrets,
    $InferenceTokenizer,
    $InferenceModel
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
$SourceRevision = (& git.exe -C $RepoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $SourceRevision -notmatch '^[0-9a-f]{40}$') {
    throw 'Repository source revision could not be resolved to a canonical Git commit.'
}
$NodeVersionOutput = (& $NodeBinary '--version' | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Node binary version probe failed.'
}
$NodeVersionMatch = [regex]::Match(
    $NodeVersionOutput,
    '^noosd (?<release>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?\+git\.(?<releaseRevision>[0-9a-f]{40})) source_revision=(?<sourceRevision>[0-9a-f]{40})$'
)
if (
    -not $NodeVersionMatch.Success -or
    $NodeVersionMatch.Groups['releaseRevision'].Value -ne $SourceRevision -or
    $NodeVersionMatch.Groups['sourceRevision'].Value -ne $SourceRevision
) {
    throw 'Node binary is not bound to the exact repository source revision.'
}
$ReleaseVersion = $NodeVersionMatch.Groups['release'].Value

$GovernanceAccount = '17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce'
$Specs = @(
    [pscustomobject]@{
        Name = 'node'
        Exe = $NodeBinary
        Args = @(
            '--observer',
            '--devnet-witness-fixture',
            '--devnet-bonsai-fixture',
            '--rpc', '127.0.0.1:29652',
            '--rpc-token-file', $TokenFile,
            '--devnet-governance-account', $GovernanceAccount,
            '--p2p-listen', '/ip4/0.0.0.0/udp/29650/quic-v1',
            '--peer', '/ip4/20.15.164.29/udp/31004/quic-v1',
            '--peer', '/ip4/172.202.41.123/udp/31005/quic-v1',
            '--peer', '/ip4/48.217.51.122/udp/31006/quic-v1',
            '--peer', '/ip4/48.217.51.122/udp/31007/quic-v1',
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
        Name = 'monitor'
        Exe = $PythonBinary
        Args = @(
            $MonitorScript,
            'serve',
            '--listen', '127.0.0.1:29901',
            '--deployment', $DeploymentManifest,
            '--evidence-dir', $MonitorEvidenceDir,
            '--signing-key', $MonitorSigningKey,
            '--r2-report', $R2Report,
            '--worker-config', $WorkerdConfig,
            '--source-revision', $SourceRevision,
            '--release-version', $ReleaseVersion,
            '--interval-seconds', '60',
            '--seed-hostname', $SeedHostname,
            '--seed-ip', $SeedIp
        )
    },
    [pscustomobject]@{
        Name = 'neural-publisher'
        Exe = $PythonBinary
        Args = @(
            $NeuralPublisherScript,
            '--hosted-config', $NeuralPublisherHostedConfig,
            '--manifest', (Join-Path $SiteRoot 'neural-manifest.json'),
            '--state', (Join-Path $NeuralPublisherStateRoot 'state.json'),
            '--evidence-dir', (Join-Path $NeuralPublisherStateRoot 'evidence'),
            '--minimum-seconds', [string]$NeuralPublisherMinimumSeconds,
            '--minimum-finalized-advance', '256',
            '--poll-seconds', '60'
        )
    },
    [pscustomobject]@{
        Name = 'seed2-rpc-fallback-tunnel'
        Exe = $SshBinary
        Args = @(
            '-NT',
            '-o', 'BatchMode=yes',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'ConnectTimeout=10',
            '-L', '127.0.0.1:39652:127.0.0.1:29652',
            $Seed2SshTarget
        )
    },
    [pscustomobject]@{
        Name = 'gateway'
        Exe = $PythonBinary
        Args = @(
            $GatewayScript,
            '--listen', '127.0.0.1:29680',
            '--monitor-url', 'http://127.0.0.1:29901',
            '--node-rpc', 'http://127.0.0.1:29652',
            '--node-token-file', $TokenFile,
            '--fallback-node-rpc', 'http://127.0.0.1:39652',
            '--fallback-node-token-file', $Seed2RpcTokenFile,
            '--site-root', $SiteRoot,
            '--wallet-api-base', $WalletApiBase,
            '--wallet-cli', $WalletCliBinary,
            '--wallet-root', (Join-Path $RepoRoot 'apps\mind-market\wallet'),
            '--wallet-faucet-db', $WalletFaucetDb,
            '--inference-secrets', $InferenceSecrets,
            '--inference-database', $InferenceDatabase,
            '--inference-worker-origin', $InferenceWorkerOrigin,
            '--inference-tokenizer', $InferenceTokenizer,
            '--inference-model', $InferenceModel,
            '--inference-tokenizer-sha256', $InferenceTokenizerSha256,
            '--allow-origin', 'https://mindchain.network',
            '--allow-origin', 'https://wwm.mindchain.network',
            '--allow-origin', 'https://wwm-rpc.mindchain.network',
            '--connect-origin', $StaticBundleOrigin,
            '--connect-origin', 'https://wwm-rpc.mindchain.network',
            '--connect-origin', 'https://wwm-seed.mindchain.network',
            '--connect-origin', 'https://wwm-seed-2.mindchain.network',
            '--connect-origin', 'https://mindchain-seed-3.eastus.cloudapp.azure.com'
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

$ProcessMarkers = @{
    'node' = $DataDir
    'artifact-store' = $ArtifactStoreRoot
    'workerd' = $WorkerdConfig
    'static-host' = $StaticHostScript
    'web-capacity' = $CoordinatorConfig
    'monitor' = $MonitorScript
    'neural-publisher' = $NeuralPublisherScript
    'gateway' = $GatewayScript
    'seed2-rpc-fallback-tunnel' = '127.0.0.1:39652:127.0.0.1:29652'
    'cloudflared' = $TunnelConfig
}
$RunningProcesses = @(Get-CimInstance Win32_Process)
foreach ($spec in $Specs) {
    $resolvedExecutable = (Get-Command -Name $spec.Exe -ErrorAction Stop).Source
    $marker = [string]$ProcessMarkers[$spec.Name]
    foreach ($candidate in $RunningProcesses) {
        if (
            $candidate.ProcessId -eq $PID -or
            -not [StringComparer]::OrdinalIgnoreCase.Equals($candidate.ExecutablePath, $resolvedExecutable) -or
            [string]::IsNullOrEmpty($candidate.CommandLine) -or
            $candidate.CommandLine.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -lt 0
        ) {
            continue
        }
        Write-Output "stopping stale $($spec.Name) pid=$($candidate.ProcessId)"
        Stop-Process -Id $candidate.ProcessId -Force -ErrorAction Stop
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
    $SupervisorMutex.ReleaseMutex()
    $SupervisorMutex.Dispose()
}
