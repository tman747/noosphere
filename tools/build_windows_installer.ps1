param(
  [Parameter(Mandatory=$true)][string]$CertificatePfx,
  [Parameter(Mandatory=$true)][string]$CertificatePassword,
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string]$OutDir = "release/installers/windows-x86_64",
  [switch]$AllowUntrustedDevelopmentCertificate
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pfx = (Resolve-Path $CertificatePfx).Path
$out = Join-Path $root $OutDir
$expectedSigner = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
  $pfx,
  $CertificatePassword,
  [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
)
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Find-SignTool {
  $roots = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots"
  $kitsRoot = $roots.KitsRoot10
  if (-not $kitsRoot) { throw "Windows SDK KitsRoot10 is unavailable" }
  $candidates = Get-ChildItem -Path (Join-Path $kitsRoot "bin") -Filter signtool.exe -Recurse |
    Where-Object { $_.FullName -match "\\x64\\signtool.exe$" } |
    Sort-Object FullName -Descending
  if ($candidates.Count -eq 0) { throw "signtool.exe x64 was not found in the Windows SDK" }
  return $candidates[0].FullName
}

Push-Location $root
try {
  node wallet/app/build.mjs
  if (-not (Get-Command cargo-tauri -ErrorAction SilentlyContinue)) {
    cargo install tauri-cli --version 2.9.6 --locked
    if ($LASTEXITCODE -ne 0) { throw "tauri-cli installation failed" }
  }
  $env:CI = "false"
  Push-Location "wallet/app/src-tauri"
  try {
    cargo tauri build --bundles msi,nsis --features gui
    if ($LASTEXITCODE -ne 0) { throw "Tauri Windows bundle failed" }
  } finally { Pop-Location }

  $targetDir = (cargo metadata --format-version 1 --no-deps | ConvertFrom-Json).target_directory
  if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed" }
  $bundleRoot = Join-Path $targetDir "release/bundle"
  $artifacts = @(Get-ChildItem $bundleRoot -Recurse -File | Where-Object { $_.Extension -in ".msi", ".exe" })
  if ($artifacts.Count -eq 0) { throw "No MSI or NSIS installer was produced" }
  $signTool = Find-SignTool
  foreach ($artifact in $artifacts) {
    & $signTool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $pfx /p $CertificatePassword $artifact.FullName
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $($artifact.FullName)" }
    $signature = Get-AuthenticodeSignature $artifact.FullName
    if ($null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $expectedSigner.Thumbprint -or
        $null -eq $signature.TimeStamperCertificate) {
      throw "Signed artifact is not bound to the requested signer and timestamp: $($artifact.FullName)"
    }
    & $signTool verify /pa /all /v $artifact.FullName
    if ($LASTEXITCODE -ne 0 -and -not $AllowUntrustedDevelopmentCertificate) {
      throw "Authenticode trust verification failed: $($artifact.FullName)"
    }
    $destination = Join-Path $out $artifact.Name
    Copy-Item -Force $artifact.FullName $destination
  }
  $manifest = @()
  Get-ChildItem $out -File | ForEach-Object {
    $signature = Get-AuthenticodeSignature $_.FullName
    if ($signature.Status -ne "Valid" -and -not $AllowUntrustedDevelopmentCertificate) {
      throw "Copied installer signature is not trusted: $($_.FullName)"
    }
    $manifest += [ordered]@{
      file = $_.Name
      sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
      signer = $signature.SignerCertificate.Subject
      thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
      timestamp = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
      trust_status = $signature.Status.ToString()
      production_trusted = ($signature.Status -eq "Valid")
    }
  }
  [ordered]@{ schema = "noos/windows-installer-signatures/v1"; artifacts = $manifest } |
    ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $out "signatures.json")
  Write-Host "Signed installers written to $out"
} finally { Pop-Location }
