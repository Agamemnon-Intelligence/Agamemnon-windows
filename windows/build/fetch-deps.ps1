<#
.SYNOPSIS
  Downloads the ClamAV and YARA Windows binaries listed in deps.json, verifies their SHA-256
  and unpacks them under windows/deps/.
.PARAMETER AllowUnpinned
  Accept a download whose sha256 is empty in deps.json (prints the hash so you can pin it).
  Never use this for release builds.
#>
param([switch]$AllowUnpinned)
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$deps = Get-Content (Join-Path $PSScriptRoot 'deps.json') -Raw | ConvertFrom-Json
$out = Join-Path $root 'deps'
New-Item -ItemType Directory -Force -Path $out | Out-Null

foreach ($name in 'clamav', 'yara') {
    $dep = $deps.$name
    $zip = Join-Path $out "$name-$($dep.version).zip"
    if (-not (Test-Path $zip)) {
        Write-Host "Downloading $name $($dep.version) from $($dep.url)"
        Invoke-WebRequest -Uri $dep.url -OutFile $zip -UseBasicParsing
    }

    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($dep.sha256)) {
        if (-not $AllowUnpinned) {
            throw "$name has no sha256 in deps.json. Verify the download, then pin: `"sha256`": `"$actual`""
        }
        Write-Warning "$name is not pinned. Downloaded file hash: $actual"
    }
    elseif ($actual -ne $dep.sha256.ToLowerInvariant()) {
        Remove-Item $zip
        throw "$name hash mismatch: expected $($dep.sha256), got $actual"
    }

    $dest = Join-Path $out $name
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Path $zip -DestinationPath $dest
    # Release zips usually wrap everything in one top-level folder; flatten it.
    $children = @(Get-ChildItem $dest)
    if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
        Get-ChildItem $children[0].FullName | Move-Item -Destination $dest
        Remove-Item $children[0].FullName
    }
    Write-Host "$name ready in $dest"
}
