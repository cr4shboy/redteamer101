<#
.SYNOPSIS
    Archive the project's own source code and produced data (text) into a zip.

.DESCRIPTION
    Creates a zip archive that contains ONLY this project's own code and the
    data it produced (Markdown, JSON, logs, etc.).

    It deliberately EXCLUDES third-party libraries, vendored runtimes and
    binaries - most notably the per-run ZAP runtime home ("zap-home") that
    holds ".jar" add-on libraries, "chromedriver.exe"/"geckodriver.exe", the
    Selenium browser extension bundle, a multi-hundred-MB ZAP session
    "untitled1.data" and other downloaded/vendored content. Caches, VCS
    metadata, node_modules and Python build artifacts are excluded as well.

    Inclusion is driven by an explicit allowlist of text/data file extensions
    (own code + produced data) plus a denylist of directory and file names, so
    nothing binary slips in by accident and the archive stays small.

.PARAMETER RepoRoot
    Repository root to archive. Defaults to the parent directory of this
    script's folder (i.e. the project root that contains this "utils" folder).

.PARAMETER OutputPath
    Destination zip file path. Defaults to
    "<RepoRoot>\..\<RepoRootName>-<yyyyMMddTHHmmssZ>.zip" (a sibling of the
    project folder) so the archive is never archived into itself.

.PARAMETER IncludeLogs
    When true (default) include "*.log" files under the produced-data folders.

.PARAMETER IncludeInventory
    When set, include the "org" folder (source workspace / org notes) if it
    exists. Off by default because that folder is not project-authored code.

.PARAMETER DryRun
    List what would be archived (with counts and sizes) and exit without
    creating a zip.

.PARAMETER Force
    Overwrite an existing output zip.

.EXAMPLE
    pwsh -File .\utils\archive_project.ps1

.EXAMPLE
    pwsh -File .\utils\archive_project.ps1 -OutputPath C:\tmp\redteam.zip -Force

.EXAMPLE
    pwsh -File .\utils\archive_project.ps1 -DryRun
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$OutputPath,
    [bool]$IncludeLogs = $true,
    [switch]$IncludeInventory,
    [switch]$DryRun,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Resolve repository root -------------------------------------------------
if (-not $RepoRoot) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepoRoot = Split-Path -Parent $scriptDir
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'src'))) {
    throw "Repository root '$RepoRoot' does not look right (no 'src' folder found)."
}

# --- Directories that must never be archived ---------------------------------
# Matched as path segments: any file whose relative path contains one of these
# segments is skipped. This removes libraries, vendored runtimes and caches.
$ExcludedDirSegments = @(
    'zap-home',            # ZAP runtime home: jars, drivers, session data, reports
    '.tools',              # project-local pinned WSL tooling (binaries, archives)
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    '.git',
    '.hg',
    '.svn',
    '.venv',
    'venv',
    'env',
    'node_modules',
    'dist',
    'build',
    '.eggs',
    'htmlcov',
    'site-packages',
    '.opencode',           # tool/runtime metadata with vendored node_modules
    '.tox',
    '.idea',
    '.vscode'
)

# --- Own code + produced-data extension allowlist ----------------------------
# Only these text/data extensions are archived. Anything else (jar, exe, dll,
# so, dylib, class, data, png, jpg, ttf, woff, css, js, ts, map, zst, ...) is
# excluded because it is a library, binary or vendored asset.
$AllowedExtensions = @(
    '.py', '.pyi',            # own Python code
    '.ps1', '.psm1', '.psd1', # own PowerShell tooling
    '.sh', '.cmd', '.bat',    # own shell entrypoints
    '.md', '.markdown',       # documentation
    '.json', '.jsonl',        # produced data + config
    '.yaml', '.yml',          # config
    '.toml', '.ini', '.cfg',  # config
    '.txt',                   # notes / produced text
    '.csv', '.tsv',           # produced tabular data
    '.xml',                   # produced reports/session text
    '.properties',            # produced ZAP/session metadata (small text)
    '.script',                # produced ZAP session metadata (small text)
    '.sql',                   # own queries/data
    '.gitignore', '.gitattributes', '.editorconfig'
)
if ($IncludeLogs) { $AllowedExtensions += '.log' }

# --- Files that must never be archived ---------------------------------------
# Recognisable binaries/, secret-bearing material and large runtime files, as a
# final guard even if a rogue extension ever matched the allowlist.
$ExcludedFileNames = @(
    'untitled1.data', 'untitled1.properties'
)
$ExcludedFilePatterns = @(
    '*.jar', '*.exe', '*.dll', '*.so', '*.dylib', '*.class', '*.bin',
    '*.data', '*.db', '*.sqlite', '*.sqlite3',
    '*.png', '*.jpg', '*.jpeg', '*.gif', '*.ico', '*.bmp', '*.webp',
    '*.ttf', '*.otf', '*.woff', '*.woff2', '*.eot',
    '*.zst', '*.gz', '*.zip', '*.7z', '*.tar', '*.rar', '*.xpi',
    '*.node', '*.pdb', '*.lib', '*.o', '*.a', '*.obj',
    '*.lck', '*.homelock', '*.jbrf',
    '*.env', '.env', '*.pem', '*.key', '*.pfx', '*.p12',
    'id_rsa', 'id_ed25519', '*.kdbx'
)

function Test-IsExcludedPath {
    param([string]$RelativePath)

    $segments = $RelativePath -split '[\\/]'
    foreach ($seg in $segments) {
        if ($ExcludedDirSegments -contains $seg) { return $true }
    }

    $leaf = $segments[-1]
    if ($ExcludedFileNames -contains $leaf) { return $true }
    foreach ($pattern in $ExcludedFilePatterns) {
        if ($leaf -like $pattern) { return $true }
    }
    return $false
}

# --- Collect files -----------------------------------------------------------
Write-Host "Repository root : $RepoRoot"
Write-Host 'Scanning project for own code and produced data ...'

$allFiles = Get-ChildItem -LiteralPath $RepoRoot -Recurse -File -Force -ErrorAction SilentlyContinue

$selected = New-Object System.Collections.Generic.List[object]
$skipped = 0
foreach ($file in $allFiles) {
    $relative = $file.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')

    if (Test-IsExcludedPath -RelativePath $relative) { $skipped++; continue }

    $ext = $file.Extension.ToLowerInvariant()
    if ($AllowedExtensions -notcontains $ext) { $skipped++; continue }

    if (-not $IncludeInventory) {
        if (($relative -split '[\\/]')[0] -eq 'org') { continue }
    }

    $selected.Add([pscustomobject]@{
        FullName = $file.FullName
        Relative = $relative
        Length   = $file.Length
    })
}

$totalBytes = ($selected | Measure-Object -Property Length -Sum).Sum
if (-not $totalBytes) { $totalBytes = 0 }

Write-Host ("Files to archive : {0}" -f $selected.Count)
Write-Host ("Skipped (libs/binaries/non-data): {0}" -f $skipped)
Write-Host ("Uncompressed size : {0:N2} MB" -f ($totalBytes / 1MB))

if ($DryRun) {
    Write-Host ''
    Write-Host '--- DRY RUN: files that WOULD be archived ---'
    $selected | Sort-Object Relative | ForEach-Object {
        Write-Host ("  {0,10:N0}  {1}" -f $_.Length, $_.Relative)
    }
    Write-Host ''
    Write-Host 'Dry run complete. No archive created.'
    return
}

if ($selected.Count -eq 0) {
    throw 'No files matched. Refusing to create an empty archive.'
}

# --- Prepare output path -----------------------------------------------------
if (-not $OutputPath) {
    $parent = Split-Path -Parent $RepoRoot
    $name = Split-Path -Leaf $RepoRoot
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $OutputPath = Join-Path $parent ("{0}-{1}.zip" -f $name, $stamp)
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

if (Test-Path -LiteralPath $OutputPath) {
    if (-not $Force) {
        throw "Output '$OutputPath' already exists. Use -Force to overwrite."
    }
    Remove-Item -LiteralPath $OutputPath -Force
}
$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# --- Stage the selected files into a flat temp tree, then compress -----------
$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("redteam-archive-" + [Guid]::NewGuid().ToString('N'))
$staging = [System.IO.Path]::GetFullPath($staging)
if (Test-Path -LiteralPath $staging) {
    Remove-Item -LiteralPath $staging -Recurse -Force
}
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    Write-Host 'Staging files ...'
    foreach ($item in $selected) {
        $destination = Join-Path $staging $item.Relative
        $destDir = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $item.FullName -Destination $destination -Force
    }

    # Small manifest so the archive is self-describing.
    $manifest = [ordered]@{
        archive_kind          = 'project-own-code-and-produced-data'
        created_utc           = [DateTime]::UtcNow.ToString('o')
        repo_root_name        = Split-Path -Leaf $RepoRoot
        file_count            = $selected.Count
        uncompressed_bytes    = $totalBytes
        excluded_dir_segments = $ExcludedDirSegments
        allowed_extensions    = $AllowedExtensions
        note                  = 'Libraries, vendored runtimes (zap-home), binaries, caches and secrets are excluded by design.'
    }
    $manifestPath = Join-Path $staging 'ARCHIVE_MANIFEST.json'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Write-Host "Compressing to '$OutputPath' ..."
    Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $OutputPath -CompressionLevel Optimal -Force

    $zipInfo = Get-Item -LiteralPath $OutputPath
    Write-Host ''
    Write-Host 'Archive created successfully.'
    Write-Host ("  Path           : {0}" -f $OutputPath)
    Write-Host ("  Archive size   : {0:N2} MB" -f ($zipInfo.Length / 1MB))
    Write-Host ("  Files included : {0}" -f $selected.Count)
    Write-Host ("  Uncompressed   : {0:N2} MB" -f ($totalBytes / 1MB))
}
finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

