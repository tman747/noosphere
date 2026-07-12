param(
    [ValidateSet(1, 2, 3)]
    [int]$WitnessIndex = 1
)

$ErrorActionPreference = "Stop"
$ExpectedHashes = @{
    1 = "3d6c5e638bff31193a3048ac8b451109b4b2f7e43c35ced2e41cdc584d1a8491"
    2 = "a7b01c66e32c8ea0967a488bcfeb429f50b2cce68ed84adeefa68079f150c4a3"
    3 = "99df34ce319d68063e153451403db826030efb707aa52f654784c29b7a656908"
}
$FileName = "MindChain-Windows-Witness-$WitnessIndex.zip"
$BundleUrl = "https://github.com/tman747/noosphere/releases/download/mindchain-lan-devnet-v1/$FileName"
$ExpectedSha256 = $ExpectedHashes[$WitnessIndex]
$Work = Join-Path $env:TEMP ("MindChain-Join-" + [guid]::NewGuid().ToString("N"))
$Archive = Join-Path $Work $FileName
$Bundle = Join-Path $Work "Bundle"

New-Item -ItemType Directory -Force $Bundle | Out-Null
try {
    Write-Host "Downloading the verified MindChain invitation..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $BundleUrl -OutFile $Archive
    $ActualSha256 = (Get-FileHash -Algorithm SHA256 -Path $Archive).Hash.ToLowerInvariant()
    if ($ActualSha256 -ne $ExpectedSha256) {
        throw "MindChain download verification failed. Expected $ExpectedSha256 but received $ActualSha256."
    }

    Expand-Archive -LiteralPath $Archive -DestinationPath $Bundle
    Get-ChildItem -LiteralPath $Bundle -Recurse -File | Unblock-File
    Write-Host "The download is verified. Adding this PC to MindChain..." -ForegroundColor Green
    $Process = Start-Process -FilePath (Join-Path $Bundle "JOIN MINDCHAIN.cmd") -Wait -PassThru
    if ($Process.ExitCode -ne 0) {
        throw "MindChain setup exited with code $($Process.ExitCode)."
    }
} finally {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
