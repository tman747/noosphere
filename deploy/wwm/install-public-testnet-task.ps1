param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$RuntimeRoot = 'C:\mindchain\wwm-testnet',
    [string]$NodeBinarySource = 'D:\noosphere-targets\public-live\debug\noosd.exe',
    [string]$TunnelConfig = 'C:\mindchain\wwm-testnet\cloudflared.yml',
    [string]$CloudflaredBinary = 'C:\mindchain\wwm-testnet\bin\cloudflared-2026.7.2.exe',
    [string]$TaskName = 'MindChainWWMTestnet',
    [switch]$StartNow
)

$ErrorActionPreference = 'Stop'
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$RuntimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$Supervisor = Join-Path $RepoRoot 'deploy\wwm\run-public-testnet.ps1'
$BinaryDir = Join-Path $RuntimeRoot 'bin'
$SecretDir = Join-Path $RuntimeRoot 'secrets'
$InstalledNode = Join-Path $BinaryDir 'noosd.exe'
$TokenFile = Join-Path $SecretDir 'rpc-token.txt'

foreach ($file in @($Supervisor, $NodeBinarySource, $TunnelConfig, $CloudflaredBinary)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required installer input is missing: $file"
    }
}
foreach ($directory in @($RuntimeRoot, $BinaryDir, $SecretDir, (Join-Path $RuntimeRoot 'node'), (Join-Path $RuntimeRoot 'logs'))) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
}
Copy-Item -LiteralPath $NodeBinarySource -Destination $InstalledNode -Force

if (-not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) {
    $bytes = New-Object byte[] 48
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [IO.File]::WriteAllText($TokenFile, "$token`n", [Text.Encoding]::ASCII)
    Remove-Variable token
}
$tokenValue = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($tokenValue.Length -lt 32 -or $tokenValue -match '\s') {
    throw 'Existing RPC token is invalid; refusing to replace it implicitly.'
}
Remove-Variable tokenValue

& icacls.exe $SecretDir /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict the testnet secret directory ACL.' }

$PowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$Supervisor`" -RepoRoot `"$RepoRoot`" -RuntimeRoot `"$RuntimeRoot`" -NodeBinary `"$InstalledNode`" -CloudflaredBinary `"$CloudflaredBinary`" -TunnelConfig `"$TunnelConfig`""
$action = New-ScheduledTaskAction -Execute $PowerShell -Argument $arguments -WorkingDirectory $RepoRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description 'Persistent WWM-capable MindChain public testnet; production effect NONE.' `
    -Force | Out-Null

if ($StartNow) { Start-ScheduledTask -TaskName $TaskName }
Write-Output "installed task=$TaskName node=$InstalledNode runtime=$RuntimeRoot start_now=$($StartNow.IsPresent)"
