# Rebuilds the synthetic fixture ZIP packages from the plaintext trees in fixtures/sources.
#
# The trees are committed in plaintext so the fixture contents stay auditable; the ZIPs are
# generated artifacts. Entry names are written with forward slashes and deterministic ordering
# so a rebuild produces the same logical package on every machine.
#
# Usage:  powershell -ExecutionPolicy Bypass -File fixtures/build-fixture-packages.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-FixturePackage {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDir,
        [Parameter(Mandatory = $true)][string]$ZipPath
    )

    $destDir = Split-Path -Parent $ZipPath
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir | Out-Null
    }
    if (Test-Path $ZipPath) {
        Remove-Item $ZipPath -Force
    }

    $base = (Resolve-Path $SourceDir).Path.TrimEnd('\')
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    try {
        Get-ChildItem -Path $SourceDir -Recurse -File | Sort-Object FullName | ForEach-Object {
            $relative = $_.FullName.Substring($base.Length + 1) -replace '\\', '/'
            $entry = $zip.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally {
                $stream.Dispose()
            }
            Write-Host ("  {0}" -f $relative)
        }
    }
    finally {
        $zip.Dispose()
    }

    Write-Host ("built {0}" -f $ZipPath)
}

$root = $PSScriptRoot

Write-Host 'gksphone-official-v1.zip'
New-FixturePackage `
    -SourceDir (Join-Path $root 'sources/gksphone-v1') `
    -ZipPath (Join-Path $root 'packages/gksphone-official-v1.zip')

Write-Host 'gksphone-update.zip'
New-FixturePackage `
    -SourceDir (Join-Path $root 'sources/gksphone-v2') `
    -ZipPath (Join-Path $root 'packages/gksphone-update.zip')
