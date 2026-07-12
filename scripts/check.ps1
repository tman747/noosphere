param(
    [switch]$DifferentialHeavy,
    [switch]$FuzzHeavy,
    [switch]$Release
)

# check.ps1 - noosphere_core_gate driver.
#
# Runs, in order, from the repository root:
#   cargo fmt --all -- --check
#   cargo clippy --workspace --all-targets -- -D warnings
#   cargo test --workspace --locked -- --test-threads=1
#   go test ./...                                  (from go/)
#   python tools/gates/validate_registry.py protocol/claims/registry.json
#   python tools/gates/check_identity.py --reject-root C:/ascent
#   python tools/gates/check_vectors.py protocol/vectors
#   python tools/gates/check_api.py
#   python tools/gates/check_telemetry.py
#   python tools/gates/check_repro_policy.py
#   python tools/gates/check_base_evidence.py
#   python tools/gates/run_claim_matrix.py --registry protocol/claims/registry.json --all-actionable --include-negative-results --require-command --require-evidence --require-rollback --fail-on-missing
#   python tools/gates/check_docs.py
#   python tools/gates/check_promotion.py
#   python tools/gates/stage_evidence.py validate
# Optional heavy switches: -DifferentialHeavy (10m transitions),
# -FuzzHeavy (2.4m mutations), and -Release (both plus supply-chain gates).
#
# Each step logs [PASS]/[FAIL]/[SKIP]. Emits `RESULT noosphere_core_gate=PASS`
# and exits 0 only when every executed step exits 0; otherwise emits
# `RESULT noosphere_core_gate=FAIL` and exits 1.
#
# Empty-workspace handling: while crates/ has no Cargo.toml children the
# cargo steps are SKIPped; while go/ has no *.go files the go step is
# SKIPped. SKIPs never satisfy a step's gate obligation once real code
# exists - they exist only so the gate is runnable from day zero.

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
$script:AnyFail = $false

function Invoke-Step {
    param(
        [string]$Name,
        [string[]]$Command,
        [string]$WorkDir
    )
    Write-Host ''
    Write-Host ("== {0} ==" -f $Name)
    $exe = $Command[0]
    $exeArgs = @()
    if ($Command.Length -gt 1) { $exeArgs = $Command[1..($Command.Length - 1)] }
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        Write-Host ("[FAIL] {0} - executable not found: {1}" -f $Name, $exe)
        $script:AnyFail = $true
        return
    }
    Push-Location $WorkDir
    try {
        & $exe @exeArgs
        $code = $LASTEXITCODE
    } catch {
        Write-Host $_
        $code = 1
    } finally {
        Pop-Location
    }
    if ($null -eq $code) { $code = 1 }
    if ($code -eq 0) {
        Write-Host ("[PASS] {0}" -f $Name)
    } else {
        Write-Host ("[FAIL] {0} (exit {1})" -f $Name, $code)
        $script:AnyFail = $true
    }
}

function Skip-Step {
    param([string]$Name, [string]$Reason)
    Write-Host ''
    Write-Host ("== {0} ==" -f $Name)
    Write-Host ("[SKIP] {0} - {1}" -f $Name, $Reason)
}

Write-Host ("noosphere_core_gate: root={0}" -f $Root)

# librocksdb-sys (noos-store's pinned RocksDB backend) runs bindgen at
# build time and needs libclang. Auto-detect when LIBCLANG_PATH is unset.
if (-not $env:LIBCLANG_PATH) {
    $swiftClangDir = 'C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin'
    $libclang = $null
    if (Test-Path (Join-Path $swiftClangDir 'libclang.dll')) {
        $libclang = @{ Source = (Join-Path $swiftClangDir 'libclang.dll') }
    } else {
        $libclang = Get-Command 'libclang.dll' -ErrorAction SilentlyContinue
    }
    if (-not $libclang) {
        $clang = Get-Command 'clang' -ErrorAction SilentlyContinue
        if ($clang) {
            $candidate = Join-Path (Split-Path -Parent $clang.Source) 'libclang.dll'
            if (Test-Path $candidate) { $libclang = @{ Source = $candidate } }
        }
    }
    if ($libclang) {
        $env:LIBCLANG_PATH = Split-Path -Parent $libclang.Source
        Write-Host ("LIBCLANG_PATH auto-detected: {0}" -f $env:LIBCLANG_PATH)
    }
}

# --- Rust workspace steps -------------------------------------------------
$cratesDir = Join-Path $Root 'crates'
$crateManifests = @()
if (Test-Path $cratesDir) {
    $crateManifests = @(Get-ChildItem -Path $cratesDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'Cargo.toml') })
}
if ($crateManifests.Count -eq 0) {
    Skip-Step 'cargo fmt' 'no crates under crates/ yet (empty workspace)'
    Skip-Step 'cargo clippy' 'no crates under crates/ yet (empty workspace)'
    Skip-Step 'cargo test' 'no crates under crates/ yet (empty workspace)'
} else {
    Invoke-Step 'cargo fmt' @('cargo', 'fmt', '--all', '--', '--check') $Root
    Invoke-Step 'cargo clippy' @('cargo', 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings') $Root
    # The node battery contains multiple RocksDB/replay and real-loopback
    # fixtures. Serial libtest scheduling preserves every test while avoiding
    # cross-fixture resource starvation that can otherwise look like a socket
    # hang on loaded builders. Claim runners use the same deterministic mode.
    Invoke-Step 'cargo test' @('cargo', 'test', '--workspace', '--locked', '--', '--test-threads=1') $Root
}

# --- Go module step -------------------------------------------------------
$goDir = Join-Path $Root 'go'
$goFiles = @()
if (Test-Path $goDir) {
    $goFiles = @(Get-ChildItem -Path $goDir -Recurse -Filter '*.go' -File -ErrorAction SilentlyContinue)
}
if ($goFiles.Count -eq 0) {
    Skip-Step 'go test' 'no *.go files under go/ yet (empty module)'
} else {
    Invoke-Step 'go test' @('go', 'test', './...') $goDir
}

# --- Python gate steps ----------------------------------------------------
Invoke-Step 'validate_registry' @('python', 'tools/gates/validate_registry.py', 'protocol/claims/registry.json') $Root
Invoke-Step 'check_identity' @('python', 'tools/gates/check_identity.py', '--reject-root', 'C:/ascent') $Root
Invoke-Step 'check_vectors' @('python', 'tools/gates/check_vectors.py', 'protocol/vectors') $Root
Invoke-Step 'check_api' @('python', 'tools/gates/check_api.py') $Root
Invoke-Step 'check_telemetry' @('python', 'tools/gates/check_telemetry.py') $Root
Invoke-Step 'check_repro_policy' @('python', 'tools/gates/check_repro_policy.py') $Root
Invoke-Step 'check_base_evidence' @('python', 'tools/gates/check_base_evidence.py') $Root
Invoke-Step 'check_mainnet_template_refusal' @('python', 'tools/gates/check_mainnet_template.py', '--self-test') $Root
Invoke-Step 'check_economics_proposal_draft' @('python', 'tools/gates/check_economics_proposal.py', '--allow-draft') $Root
Invoke-Step 'check_docs' @('python', 'tools/gates/check_docs.py') $Root
Invoke-Step 'check_promotion' @('python', 'tools/gates/check_promotion.py') $Root
Invoke-Step 'stage_evidence' @('python', 'tools/gates/stage_evidence.py', 'validate') $Root
Invoke-Step 'differential_transitions_smoke' @('python', 'tools/gates/differential_transitions.py', '--generated', '500', '--restart-every', '100') $Root

if ($DifferentialHeavy -or $Release) {
    Invoke-Step 'differential_transitions_10m' @('python', 'tools/gates/differential_transitions.py', '--generated', '10000000') $Root
}
if ($FuzzHeavy -or $Release) {
    $previousFuzzIters = $env:NOOS_FUZZ_ITERS
    $env:NOOS_FUZZ_ITERS = '2400000'
    Invoke-Step 'decoder_vm_protocol_battery_2_4m' @('cargo', 'test', '-p', 'noos-fuzz', '--test', 'decoder_vm_protocol_battery', '--', '--nocapture') $Root
    $env:NOOS_FUZZ_ITERS = $previousFuzzIters
}
if ($Release) {
    Invoke-Step 'run_claim_matrix_release' @('python', 'tools/gates/run_claim_matrix.py', '--registry', 'protocol/claims/registry.json', '--all-actionable', '--include-negative-results', '--require-command', '--require-evidence', '--require-rollback', '--fail-on-missing') $Root
    Invoke-Step 'client_matrix' @('python', 'tools/e2e/run_network.py', '--scenario', 'client-matrix', '--pairs', 'AA,AB,BA,BB') $Root
    Invoke-Step 'repro_external_attestations' @('python', 'tools/gates/repro_build.py', 'verify-attestations', '--attestations', 'release/attestations', '--trusted-builders', 'protocol/release/trusted-repro-builders.json', '--keyring', 'release/role-keyring.json', '--final-freeze', 'release/final-freeze.json', '--final-freeze-signatures', 'release/final-freeze.signatures.json', '--out', 'release/repro-assurance.json') $Root
    Invoke-Step 'verify_release' @('python', 'tools/gates/verify_release.py', 'release/manifest.json', '--keyring', 'release/role-keyring.json', '--final-freeze', 'release/final-freeze.json', '--final-freeze-signatures', 'release/final-freeze.signatures.json', '--repro-assurance', 'release/repro-assurance.json') $Root
}

# --- Verdict ----------------------------------------------------------------
Write-Host ''
if ($script:AnyFail) {
    Write-Host 'RESULT noosphere_core_gate=FAIL'
    exit 1
}
Write-Host 'RESULT noosphere_core_gate=PASS'
exit 0
