param(
    [string]$NetworkRoot = "C:\tmp\mindchain-lan-proof",
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$Tailscale = Get-Command tailscale.exe -ErrorAction SilentlyContinue
if (-not $Tailscale) {
    throw "Tailscale is not installed. Install it and authenticate this host before remote onboarding."
}
$Status = & $Tailscale.Source status --json | ConvertFrom-Json
if ($Status.BackendState -ne "Running") {
    throw "Tailscale is not connected. Current state: $($Status.BackendState)"
}
$TailnetIp = @($Status.Self.TailscaleIPs | Where-Object { $_ -match '^100\.' }) | Select-Object -First 1
if (-not $TailnetIp) {
    throw "Tailscale did not report an IPv4 address in 100.64.0.0/10."
}
$Launcher = Join-Path $PSScriptRoot "start_invitation_host.ps1"
$Arguments = @(
    "-NetworkRoot", $NetworkRoot,
    "-ExpectedHost", [string]$TailnetIp,
    "-NetworkMode", "Tailscale"
)
if ($CheckOnly) { $Arguments += "-CheckOnly" }
& $Launcher @Arguments
