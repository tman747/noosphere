param([string]$BundleRoot = $PSScriptRoot)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName PresentationFramework

function Fail([string]$Message) {
  [System.Windows.MessageBox]::Show($Message, "MindChain setup", "OK", "Error") | Out-Null
  exit 1
}

try {
  $invitePath = Join-Path $BundleRoot "invite.json"
  $nodeSource = Join-Path $BundleRoot "noosd.exe"
  $paramsSource = Join-Path $BundleRoot "devnet-parameters.toml"
  if (-not (Test-Path $invitePath) -or -not (Test-Path $nodeSource) -or -not (Test-Path $paramsSource)) {
    Fail "This MindChain invitation is incomplete. Download the bundle again."
  }
  $invite = Get-Content -Raw $invitePath | ConvertFrom-Json
  if ($invite.schema -ne "noos/one-click-invite/v1") { Fail "This invitation format is not supported." }
  $paramsHash = (Get-FileHash $paramsSource -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($paramsHash -ne $invite.params_sha256) { Fail "The network parameters failed their checksum." }

  $installRoot = Join-Path $env:LOCALAPPDATA "MindChain\Operator"
  $dataRoot = Join-Path $env:LOCALAPPDATA "MindChain\NodeData"
  New-Item -ItemType Directory -Force $installRoot,$dataRoot | Out-Null
  Copy-Item -Force $nodeSource (Join-Path $installRoot "noosd.exe")
  Copy-Item -Force $paramsSource (Join-Path $installRoot "devnet-parameters.toml")
  Copy-Item -Force $invitePath (Join-Path $installRoot "invite.json")

  $args = @(
    "--params", (Join-Path $installRoot "devnet-parameters.toml"),
    "--data-dir", $dataRoot,
    "--genesis-time", [string]$invite.genesis_time_ms,
    "--p2p-listen", "/ip4/0.0.0.0/udp/$($invite.local_p2p_port)/quic-v1",
    "--peer", "/ip4/$($invite.validator_host)/udp/$($invite.validator_p2p_port)/quic-v1",
    "--observer", "--devnet-contract-fixture", "--devnet-witness", [string]$invite.witness_index
  )
  foreach ($account in $invite.wallet_accounts) { $args += @("--devnet-account", [string]$account) }
  $quoted = $args | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }
  $launcher = "`$ErrorActionPreference='Stop'`n& '$(Join-Path $installRoot "noosd.exe")' $($quoted -join ' ')`n"
  $launcherPath = Join-Path $installRoot "run-node.ps1"
  Set-Content -Encoding utf8 $launcherPath $launcher

  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  $settings = New-ScheduledTaskSettingsSet -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 3650)
  Register-ScheduledTask -TaskName "MindChain Node" -Action $action -Trigger $trigger -Settings $settings -Description "MindChain LAN witness node" -Force | Out-Null
  Start-ScheduledTask -TaskName "MindChain Node"

  if ($invite.compute_market_url) { Start-Process [string]$invite.compute_market_url }
  [System.Windows.MessageBox]::Show(
    "This computer is now helping the MindChain network. It will reconnect automatically when you sign in. Keep this invitation private to your engineering network.",
    "MindChain is running", "OK", "Information"
  ) | Out-Null
} catch {
  Fail $_.Exception.Message
}
