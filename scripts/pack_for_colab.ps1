<#
    pack_for_colab.ps1 - build the two zips that the Colab notebook expects.

    The Colab runtime is a remote VM: it cannot see this machine's files. Code and
    data have to travel via Google Drive. They are split into two archives because
    the code changes constantly (~200 KB, cheap to re-upload) while the data slices
    do not (~75 MB, upload once).

    Usage (from the repo root):
        powershell -ExecutionPolicy Bypass -File scripts\pack_for_colab.ps1

    Then upload the archives from dist\colab\ to Google Drive:
        MyDrive\introspect-ai\introspect_code.zip
        MyDrive\introspect-ai\introspect_data.zip   (only when the slices change)
#>

[CmdletBinding()]
param(
    # Skip the large data archive; useful for the common "I only changed code" case.
    [switch]$CodeOnly
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Backend  = Join-Path $RepoRoot "backend"
$OutDir   = Join-Path $RepoRoot "dist\colab"
$Staging  = Join-Path $env:TEMP "introspect_colab_stage"

if (-not (Test-Path $Backend)) { throw "backend\ not found under $RepoRoot" }
if (-not (Test-Path $OutDir))  { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

# ── Code archive ────────────────────────────────────────────────────────────
# Staged rather than zipped in place so venv\, checkpoints\ and data\raw\ (1.3 GB)
# are excluded rather than compressed and then discarded.
if (Test-Path $Staging) { Remove-Item -Recurse -Force $Staging }
New-Item -ItemType Directory -Force -Path (Join-Path $Staging "backend") | Out-Null

Copy-Item (Join-Path $Backend "train.py")   (Join-Path $Staging "backend") -Force
Copy-Item (Join-Path $Backend "pytest.ini") (Join-Path $Staging "backend") -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Backend "requirements.txt") (Join-Path $Staging "backend") -Force -ErrorAction SilentlyContinue

Copy-Item (Join-Path $Backend "app")   (Join-Path $Staging "backend\app")   -Recurse -Force
Copy-Item (Join-Path $Backend "tests") (Join-Path $Staging "backend\tests") -Recurse -Force -ErrorAction SilentlyContinue

# mock_cicids.csv is what --smoke runs against, so it has to ship with the code.
$SampleDst = Join-Path $Staging "backend\data\samples"
New-Item -ItemType Directory -Force -Path $SampleDst | Out-Null
Copy-Item (Join-Path $Backend "data\samples\*") $SampleDst -Force

# Byte-compiled leftovers confuse nothing but waste space.
Get-ChildItem $Staging -Recurse -Directory -Filter "__pycache__" |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
Get-ChildItem $Staging -Recurse -Directory -Filter ".pytest_cache" |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }

$CodeZip = Join-Path $OutDir "introspect_code.zip"
if (Test-Path $CodeZip) { Remove-Item -Force $CodeZip }
Compress-Archive -Path (Join-Path $Staging "backend") -DestinationPath $CodeZip -CompressionLevel Optimal
Remove-Item -Recurse -Force $Staging

$CodeMb = [math]::Round((Get-Item $CodeZip).Length / 1MB, 2)
Write-Host "code -> $CodeZip ($CodeMb MB)"

# ── Data archive ────────────────────────────────────────────────────────────
if ($CodeOnly) {
    Write-Host "-CodeOnly given; skipping the data archive."
} else {
    # Exactly the five slices train.py reads. The full-day CSVs stay behind.
    $Slices = @(
        "monday_plus_slice.csv",
        "tuesday_plus_slice.csv",
        "wednesday_plus_slice.csv",
        "thursday_plus_slice.csv",
        "friday_plus_slice_mixed.csv"
    )

    $Paths = @()
    foreach ($s in $Slices) {
        $p = Join-Path $Backend "data\raw\$s"
        if (-not (Test-Path $p)) { throw "Missing data slice: $p" }
        $Paths += $p
    }

    $DataZip = Join-Path $OutDir "introspect_data.zip"
    if (Test-Path $DataZip) { Remove-Item -Force $DataZip }
    Write-Host "Compressing 5 slices (~300 MB raw); this takes a minute..."
    Compress-Archive -Path $Paths -DestinationPath $DataZip -CompressionLevel Optimal

    $DataMb = [math]::Round((Get-Item $DataZip).Length / 1MB, 2)
    Write-Host "data -> $DataZip ($DataMb MB)"
}

Write-Host ""
Write-Host "Upload to Google Drive under:  MyDrive\introspect-ai\"
Write-Host "Then run notebooks\colab_train.ipynb against a Colab runtime."
