# check.ps1 - noosphere_core_gate driver.
#
# Runs, in order, from the repository root:
#   cargo fmt --all -- --check
#   cargo clippy --workspace --all-targets -- -D warnings
#   cargo test --workspace --locked
#   go test ./...                                  (from go/)
#   python tools/gates/validate_registry.py protocol/claims/registry.json
#   python tools/gates/check_identity.py --reject-root C:/ascent
#   python tools/gates/check_vectors.py protocol/vectors
#   python tools/gates/check_api.py
#   python tools/gates/check_telemetry.py
#   python tools/gates/check_repro_policy.py
#   python tools/gates/check_base_evidence.py
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
    Invoke-Step 'cargo test' @('cargo', 'test', '--workspace', '--locked') $Root
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

# --- Verdict ----------------------------------------------------------------
Write-Host ''
if ($script:AnyFail) {
    Write-Host 'RESULT noosphere_core_gate=FAIL'
    exit 1
}
Write-Host 'RESULT noosphere_core_gate=PASS'
exit 0
