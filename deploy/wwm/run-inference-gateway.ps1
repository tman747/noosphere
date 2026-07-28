param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$RuntimeRoot = 'C:\mindchain\wwm-testnet',
    [string]$PythonBinary = 'C:\Users\ntrap\AppData\Local\Programs\Python\Python310\python.exe',
    [string]$Listen = '127.0.0.1:29831',
    [string]$MonitorUrl = 'http://127.0.0.1:29901',
    [string]$NodeRpc = 'http://127.0.0.1:29652',
    [string]$NodeTokenFile = 'C:\mindchain\wwm-testnet\secrets\rpc-token.txt',
    [string]$FallbackNodeRpc = 'http://127.0.0.1:39652',
    [string]$FallbackNodeTokenFile = 'C:\mindchain\wwm-testnet\secrets\seed2-rpc-token.txt',
    [string]$WalletApiBase = 'https://wwm-seed-2.mindchain.network',
    [string]$WalletCli = 'D:\noosphere-targets\compat-release-windows-49e097e-v1\release\noos-cli.exe',
    [string]$WalletFaucetDatabase = 'C:\mindchain\wwm-testnet\wallet\faucet.sqlite3',
    [string]$InferenceSecrets = 'C:\mindchain\wwm-testnet\secrets\public-inference.json',
    [string]$InferenceDatabase = 'C:\mindchain\wwm-testnet\inference\public-inference.sqlite3',
    [string]$InferenceHostedConfig = 'C:\mindchain\wwm-testnet\secrets\hosted-model-publisher-49e097e.json',
    [string]$InferenceWorkerOrigin = 'http://127.0.0.1:29807',
    [string]$InferenceWorkerConfig = 'C:\mindchain\wwm-testnet\secrets\workerd.toml',
    [string]$InferenceWorkerBinary = 'D:\noosphere-targets\compat-release-windows-49e097e-v1\release\noos-workerd.exe',
    [string]$InferenceTokenizer = 'D:\noosphere-artifacts\runtime\hip-run\llama-tokenize.exe',
    [string]$InferenceModel = 'D:\noosphere-artifacts\demo-disposable\model\Bonsai-27B-Q1_0.gguf',
    [string]$InferenceTokenizerSha256 = '2685f72d8b2c27c72c116d2c6af9bb180adb4bf2f4fc9adee052dbcfe7f266f4',
    [string]$CoreSourceRevision = '49e097e3065dfc2c7522ba5cc5c7c56b88e6fd51',
    [string]$CoreReleaseVersion = '0.1.0+git.49e097e3065dfc2c7522ba5cc5c7c56b88e6fd51',
    [string]$ChainId = '0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b',
    [string]$GenesisHash = '8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e',
    [Parameter(Mandatory = $true)]
    [string]$SourceRevision,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseVersion
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-kill-on-close-job.ps1')

$CreatedMutex = $false
$SupervisorMutex = [Threading.Mutex]::new(
    $true,
    'Local\MindChainInferenceGatewaySupervisor',
    [ref]$CreatedMutex
)
if (-not $CreatedMutex) {
    $SupervisorMutex.Dispose()
    throw 'Another inference gateway supervisor is already running.'
}

$Child = $null
$JobHandle = [MindChainKillOnCloseJob]::Create()
try {
    $RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
    $RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
    $GatewayScript = Join-Path $RepoRoot 'tools\operations\wwm_public_gateway.py'
    $InferenceScript = Join-Path $RepoRoot 'tools\operations\wwm_public_inference.py'
    $SettlementScript = Join-Path $RepoRoot 'tools\operations\wwm_public_settlement.py'
    $JobHelper = Join-Path $PSScriptRoot 'windows-kill-on-close-job.ps1'
    $SiteRoot = Join-Path $RepoRoot 'site'
    $WalletRoot = Join-Path $RepoRoot 'apps\mind-market\wallet'
    $LogRoot = Join-Path $RuntimeRoot 'logs'
    $EvidenceRoot = Join-Path $RuntimeRoot 'inference-campaign'
    New-Item -ItemType Directory -Force -Path $LogRoot, $EvidenceRoot | Out-Null

    foreach ($file in @(
        $PythonBinary,
        $GatewayScript,
        $InferenceScript,
        $SettlementScript,
        $JobHelper,
        $NodeTokenFile,
        $FallbackNodeTokenFile,
        $WalletCli,
        $InferenceSecrets,
        $InferenceHostedConfig,
        $InferenceWorkerConfig,
        $InferenceWorkerBinary,
        $InferenceTokenizer,
        $InferenceModel
    )) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Required inference gateway file is missing: $file"
        }
    }
    foreach ($directory in @($SiteRoot, $WalletRoot)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            throw "Required inference gateway directory is missing: $directory"
        }
    }
    if ($SourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw 'Inference gateway source revision must be canonical lowercase hex40.'
    }
    if ($ReleaseVersion -ne "0.1.0+git.$SourceRevision") {
        throw 'Inference gateway release version is not bound to its source revision.'
    }
    if ($CoreSourceRevision -notmatch '^[0-9a-f]{40}$' -or $CoreReleaseVersion -ne "0.1.0+git.$CoreSourceRevision") {
        throw 'Core release identity is not exact.'
    }
    if ($ChainId -notmatch '^[0-9a-f]{64}$' -or $GenesisHash -notmatch '^[0-9a-f]{64}$') {
        throw 'Inference gateway chain identity is not canonical.'
    }
    $ResolvedRevision = (& git.exe -C $RepoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $ResolvedRevision -ne $SourceRevision) {
        throw 'Inference gateway repository does not match the requested source revision.'
    }
    & git.exe -C $RepoRoot diff --quiet -- `
        tools/operations/wwm_public_gateway.py `
        tools/operations/wwm_public_inference.py `
        tools/operations/wwm_public_settlement.py `
        deploy/wwm/run-inference-gateway.ps1 `
        deploy/wwm/windows-kill-on-close-job.ps1
    if ($LASTEXITCODE -ne 0) {
        throw 'Inference gateway source files differ from the exact repository revision.'
    }

    $NodeToken = (Get-Content -LiteralPath $NodeTokenFile -Raw).Trim()
    if ($NodeToken.Length -lt 32 -or $NodeToken -match '\s') {
        throw 'Inference gateway node token is invalid.'
    }
    $NodeStatus = Invoke-RestMethod `
        -Uri "$NodeRpc/status" `
        -Headers @{ Authorization = "Bearer $NodeToken" } `
        -TimeoutSec 15
    if (
        [string]$NodeStatus.chain_id -ne $ChainId -or
        [string]$NodeStatus.genesis_hash -ne $GenesisHash -or
        [string]$NodeStatus.source_revision -ne $CoreSourceRevision -or
        [string]$NodeStatus.release_version -ne $CoreReleaseVersion
    ) {
        throw 'Inference gateway core node identity does not match the exact deployment.'
    }

    $TrackedFiles = [ordered]@{
        gateway_sha256 = (Get-FileHash -LiteralPath $GatewayScript -Algorithm SHA256).Hash.ToLowerInvariant()
        inference_sha256 = (Get-FileHash -LiteralPath $InferenceScript -Algorithm SHA256).Hash.ToLowerInvariant()
        settlement_sha256 = (Get-FileHash -LiteralPath $SettlementScript -Algorithm SHA256).Hash.ToLowerInvariant()
        job_helper_sha256 = (Get-FileHash -LiteralPath $JobHelper -Algorithm SHA256).Hash.ToLowerInvariant()
        python_sha256 = (Get-FileHash -LiteralPath $PythonBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        worker_binary_sha256 = (Get-FileHash -LiteralPath $InferenceWorkerBinary -Algorithm SHA256).Hash.ToLowerInvariant()
        worker_config_sha256 = (Get-FileHash -LiteralPath $InferenceWorkerConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        hosted_config_sha256 = (Get-FileHash -LiteralPath $InferenceHostedConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        inference_secrets_sha256 = (Get-FileHash -LiteralPath $InferenceSecrets -Algorithm SHA256).Hash.ToLowerInvariant()
        tokenizer_sha256 = (Get-FileHash -LiteralPath $InferenceTokenizer -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($TrackedFiles.tokenizer_sha256 -ne $InferenceTokenizerSha256) {
        throw 'Inference gateway tokenizer hash does not match the exact deployment.'
    }
    $Deployment = [ordered]@{
        schema = 'noos/wwm-inference-service-deployment/v1'
        source_revision = $SourceRevision
        release_version = $ReleaseVersion
        core_source_revision = $CoreSourceRevision
        core_release_version = $CoreReleaseVersion
        chain_id = $ChainId
        genesis_hash = $GenesisHash
        listen = $Listen
        public_origin = 'https://wwm.mindchain.network'
        public_route = '/api/wwm/v2'
        monitor_url = $MonitorUrl
        node_rpc = $NodeRpc
        fallback_node_rpc = $FallbackNodeRpc
        inference_worker_origin = $InferenceWorkerOrigin
        inference_database = [IO.Path]::GetFullPath($InferenceDatabase)
        model_artifact_sha256 = '17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0'
        files = $TrackedFiles
        production = $false
        promotion_effect = 'NONE'
    }
    $DeploymentJson = ($Deployment | ConvertTo-Json -Depth 4) + "`n"
    $DeploymentPath = Join-Path $EvidenceRoot "deployment-$SourceRevision.json"
    if (Test-Path -LiteralPath $DeploymentPath -PathType Leaf) {
        if ((Get-Content -LiteralPath $DeploymentPath -Raw) -ne $DeploymentJson) {
            throw 'Existing inference deployment receipt does not match the exact runtime.'
        }
    } else {
        $Bytes = [Text.UTF8Encoding]::new($false).GetBytes($DeploymentJson)
        $Stream = [IO.File]::Open($DeploymentPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $Stream.Write($Bytes, 0, $Bytes.Length)
            $Stream.Flush($true)
        } finally {
            $Stream.Dispose()
        }
    }
    $DeploymentSha256 = (Get-FileHash -LiteralPath $DeploymentPath -Algorithm SHA256).Hash.ToLowerInvariant()

    $Arguments = @(
        $GatewayScript,
        '--listen', $Listen,
        '--monitor-url', $MonitorUrl,
        '--node-rpc', $NodeRpc,
        '--node-token-file', $NodeTokenFile,
        '--fallback-node-rpc', $FallbackNodeRpc,
        '--fallback-node-token-file', $FallbackNodeTokenFile,
        '--site-root', $SiteRoot,
        '--wallet-api-base', $WalletApiBase,
        '--wallet-cli', $WalletCli,
        '--wallet-root', $WalletRoot,
        '--wallet-faucet-db', $WalletFaucetDatabase,
        '--inference-secrets', $InferenceSecrets,
        '--inference-database', $InferenceDatabase,
        '--inference-hosted-config', $InferenceHostedConfig,
        '--inference-worker-origin', $InferenceWorkerOrigin,
        '--inference-tokenizer', $InferenceTokenizer,
        '--inference-model', $InferenceModel,
        '--inference-tokenizer-sha256', $InferenceTokenizerSha256,
        '--allow-origin', 'https://mindchain.network',
        '--allow-origin', 'https://wwm.mindchain.network',
        '--allow-origin', 'https://wwm-rpc.mindchain.network',
        '--connect-origin', 'https://wwm-artifacts.mindchain.network',
        '--connect-origin', 'https://wwm-rpc.mindchain.network',
        '--connect-origin', 'https://wwm-seed.mindchain.network',
        '--connect-origin', 'https://wwm-seed-2.mindchain.network',
        '--connect-origin', 'https://mindchain-seed-3.eastus.cloudapp.azure.com'
    )
    $BackoffSeconds = 1
    while ($true) {
        $Stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        $Stdout = Join-Path $LogRoot "inference-gateway-$Stamp.log"
        $Stderr = Join-Path $LogRoot "inference-gateway-$Stamp.err.log"
        $StartedAt = [DateTimeOffset]::UtcNow
        $Child = Start-Process `
            -FilePath $PythonBinary `
            -ArgumentList $Arguments `
            -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $Stdout `
            -RedirectStandardError $Stderr `
            -WindowStyle Hidden `
            -PassThru
        try {
            [MindChainKillOnCloseJob]::Assign($JobHandle, $Child.Handle)
        } catch {
            if (-not $Child.HasExited) {
                Stop-Process -Id $Child.Id -Force -ErrorAction SilentlyContinue
            }
            throw
        }
        Write-Output "started inference gateway pid=$($Child.Id) deployment_sha256=$DeploymentSha256 stdout=$Stdout stderr=$Stderr"
        $Child.WaitForExit()
        $ExitCode = $Child.ExitCode
        $Uptime = ([DateTimeOffset]::UtcNow - $StartedAt).TotalMinutes
        if ($Uptime -ge 5) {
            $BackoffSeconds = 1
        }
        Write-Error "inference gateway exited code=$ExitCode; restarting after ${BackoffSeconds}s" -ErrorAction Continue
        Start-Sleep -Seconds $BackoffSeconds
        $BackoffSeconds = [Math]::Min(60, $BackoffSeconds * 2)
        $Child = $null
    }
} finally {
    if ($null -ne $Child -and -not $Child.HasExited) {
        Stop-Process -Id $Child.Id -Force -ErrorAction SilentlyContinue
    }
    [MindChainKillOnCloseJob]::Close($JobHandle)
    $SupervisorMutex.ReleaseMutex()
    $SupervisorMutex.Dispose()
}
