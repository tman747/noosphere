$ErrorActionPreference = "Stop"

$methodRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $methodRoot "../../..")
$linuxRoot = (wsl.exe -e wslpath -a ($methodRoot -replace '\\', '/')).Trim()

wsl.exe -e bash -lc "cd '$linuxRoot' && NOOS_REBUILD_RISC0_GUEST=1 cargo check --locked -p noos-jet-risc0-methods"
if ($LASTEXITCODE -ne 0) {
    throw "RISC Zero guest build failed"
}

$generated = Join-Path $methodRoot "target/riscv-guest/noos-jet-risc0-methods/noos-jet-risc0-guest/riscv32im-risc0-zkvm-elf/docker/jet_proof.bin"
$committed = Join-Path $methodRoot "artifacts/jet_proof.bin"
if (-not (Test-Path -LiteralPath $generated)) {
    throw "generated combined method binary is missing: $generated"
}
$generatedHash = (Get-FileHash -LiteralPath $generated -Algorithm SHA256).Hash
$committedHash = (Get-FileHash -LiteralPath $committed -Algorithm SHA256).Hash
if ($generatedHash -ne $committedHash) {
    throw "guest artifact mismatch: generated=$generatedHash committed=$committedHash"
}

Write-Output "RESULT risc0_guest_reproducible=PASS"
Write-Output "SHA256 $generatedHash"
Write-Output "REPO $repoRoot"
