# Rebuild AdDehydrationKit.zip from the ADDS directory.
#
# The script lives in ADDS/Tools/ but targets the parent ADDS/ folder
# so it packages the full kit, not just the Tools subfolder.
#
# Uses the .NET ZipFile API directly because Compress-Archive in
# PS 5.1 silently skips hidden files (GPO bkupInfo.xml etc.).
#
# Usage: .\Build-Zip.ps1          (from anywhere inside ADDS)

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Root is ADDS/ (one level up from Tools/)
$here = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

# Read version from the module manifest (single source of truth)
$psd1Path = Join-Path $here 'AdDehydrationKit\AdDehydrationKit.psd1'
$manifest = Import-PowerShellDataFile $psd1Path
$version  = $manifest.ModuleVersion

$zipName = "AdDehydrationKit-v$version.zip"
$zipPath = Join-Path $here $zipName

# Remove old zip(s) - including prior versions
Get-ChildItem -Path $here -Filter 'AdDehydrationKit*.zip' -File |
    Remove-Item -Force

# Enumerate all files, including hidden, excluding what should not ship
# OUStructure.csv is generated at runtime by New-AdkOuTree and must not
# ship in the zip - a stale copy causes token-resolution errors when
# individual steps are run without OuTree on a different environment.
$excludeFiles = @('OUStructure.csv')
$excludeExt   = @('.docx')
$exclude = @('.deprecated', 'Tools')
$files   = Get-ChildItem -Path $here -Recurse -Force -File |
           Where-Object {
               $rel = $_.FullName.Substring($here.Length + 1)
               $topDir = ($rel -split '[\\/]')[0]
               ($exclude -notcontains $topDir) -and ($excludeFiles -notcontains $_.Name) -and ($excludeExt -notcontains $_.Extension) -and ($_.Name -notlike 'AdDehydrationKit*.zip')
           }

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
try {
    foreach ($f in $files) {
        $entry = $f.FullName.Substring($here.Length + 1).Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, $f.FullName, $entry, 'Optimal') | Out-Null
    }
} finally {
    $zip.Dispose()
}

Write-Host "Created $zipPath ($('{0:N0}' -f (Get-Item $zipPath).Length) bytes)" -ForegroundColor Green
