param(
  [Parameter(Mandatory=$true)][string]$JoinBundle,
  [Parameter(Mandatory=$true)][string]$OutputExe,
  [Parameter(Mandatory=$true)][string]$CertificatePfx,
  [Parameter(Mandatory=$true)][string]$CertificatePassword,
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$bundle = (Resolve-Path $JoinBundle).Path
$pfx = (Resolve-Path $CertificatePfx).Path
$output = [IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputExe))
$nsis = Join-Path $env:LOCALAPPDATA "tauri\NSIS\makensis.exe"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
if (-not (Test-Path $nsis)) { throw "NSIS compiler not found: $nsis" }
if (-not (Test-Path $signtool)) { throw "Windows signtool not found: $signtool" }
New-Item -ItemType Directory -Force (Split-Path $output) | Out-Null
$temp = Join-Path $env:TEMP ("mindchain-join-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $temp | Out-Null
try {
  Expand-Archive -LiteralPath $bundle -DestinationPath $temp
  foreach ($required in @("noosd.exe","invite.json","devnet-parameters.toml","operator_onboard.ps1")) {
    if (-not (Test-Path (Join-Path $temp $required))) { throw "Join bundle missing $required" }
  }
  $source = $temp.Replace("\", "\\")
  $outEscaped = $output.Replace("\", "\\")
  $script = @"
Unicode True
Name "MindChain Network"
OutFile "$outEscaped"
InstallDir "`$LOCALAPPDATA\MindChain\Invitation"
RequestExecutionLevel user
ShowInstDetails nevershow
Page instfiles
Section "Join MindChain"
  SetOutPath "`$INSTDIR"
  File "$source\noosd.exe"
  File "$source\invite.json"
  File "$source\devnet-parameters.toml"
  File "$source\operator_onboard.ps1"
  ExecWait 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "`$INSTDIR\operator_onboard.ps1" -BundleRoot "`$INSTDIR"' `$0
  IntCmp `$0 0 done
  Abort "MindChain onboarding did not complete."
  done:
SectionEnd
"@
  $nsi = Join-Path $temp "join.nsi"
  Set-Content -LiteralPath $nsi -Encoding utf8 $script
  & $nsis $nsi
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $output)) { throw "NSIS join installer build failed" }
  & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $pfx /p $CertificatePassword $output
  if ($LASTEXITCODE -ne 0) { throw "Join installer signing failed" }
  $signature = Get-AuthenticodeSignature $output
  if ($null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
    throw "Join installer signature or timestamp is missing"
  }
  [ordered]@{
    schema = "noos/windows-join-installer/v1"
    file = [IO.Path]::GetFileName($output)
    sha256 = (Get-FileHash $output -Algorithm SHA256).Hash.ToLowerInvariant()
    signer = $signature.SignerCertificate.Subject
    thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
    trust_status = $signature.Status.ToString()
    production_trusted = ($signature.Status -eq "Valid")
    timestamped = ($null -ne $signature.TimeStamperCertificate)
  } | ConvertTo-Json | Set-Content -Encoding utf8 ($output + ".json")
  Write-Host "Built $output"
} finally {
  Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
